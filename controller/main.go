package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/protobuf/proto"
)

const routeTableName = "ipv4_lpm"

type options struct {
	address      string
	deviceID     uint64
	p4infoPath   string
	deviceConfig string
	timeout      time.Duration
	verifyOnly   bool
}

type route struct {
	prefix string
	port   uint64
	srcMAC string
	dstMAC string
}

var routes = []route{
	{
		prefix: "10.0.1.0",
		port:   1,
		srcMAC: "02:00:00:00:01:fe",
		dstMAC: "02:00:00:00:01:01",
	},
	{
		prefix: "10.0.2.0",
		port:   2,
		srcMAC: "02:00:00:00:02:fe",
		dstMAC: "02:00:00:00:02:01",
	},
	{
		prefix: "10.0.3.0",
		port:   3,
		srcMAC: "02:00:00:00:03:fe",
		dstMAC: "02:00:00:00:03:01",
	},
}

func main() {
	log.SetFlags(0)
	opts, err := parseOptions()
	if err != nil {
		log.Fatal(err)
	}

	signalContext, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, opts.timeout)
	defer cancel()

	if err := run(ctx, opts); err != nil {
		log.Fatal(err)
	}
}

func parseOptions() (options, error) {
	var opts options
	flag.StringVar(&opts.address, "address", "127.0.0.1:50051", "P4Runtime server address")
	flag.Uint64Var(&opts.deviceID, "device-id", 1, "P4Runtime device ID")
	flag.StringVar(&opts.p4infoPath, "p4info", "build/qos.p4info.txtpb", "P4Info text protobuf")
	flag.StringVar(&opts.deviceConfig, "device-config", "build/qos.json", "BMv2 device configuration")
	flag.DurationVar(&opts.timeout, "timeout", 10*time.Second, "controller operation timeout")
	flag.BoolVar(&opts.verifyOnly, "verify-only", false, "verify switch state without writing")
	flag.Parse()

	if flag.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	if opts.deviceID == 0 {
		return options{}, errors.New("device ID must be nonzero")
	}
	if opts.timeout <= 0 {
		return options{}, errors.New("timeout must be positive")
	}
	return opts, nil
}

func run(ctx context.Context, opts options) error {
	want, err := loadPipeline(opts.p4infoPath, opts.deviceConfig)
	if err != nil {
		return err
	}
	wantRoutes, err := buildRouteEntries(want)
	if err != nil {
		return err
	}

	controller, err := client.Dial(
		ctx,
		opts.address,
		client.WithDeviceID(opts.deviceID),
		client.WithElectionID(client.ElectionID{Low: 1}),
		client.WithInsecure(),
		client.WithArbitrationTimeout(opts.timeout),
	)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", opts.address, err)
	}
	defer controller.Close()

	if err := controller.BecomePrimary(ctx); err != nil {
		return fmt.Errorf("become primary: %w", err)
	}
	if !opts.verifyOnly {
		if _, err := controller.SetPipeline(ctx, want, client.SetPipelineOptions{}); err != nil {
			return fmt.Errorf("install pipeline: %w", err)
		}

		updates := make([]*p4v1.Update, 0, len(wantRoutes))
		for _, entry := range wantRoutes {
			updates = append(updates, client.TableEntryUpdate(client.UpdateInsert, entry))
		}
		if err := controller.Write(ctx, client.WriteOptions{}, updates...); err != nil {
			return fmt.Errorf("install IPv4 routes: %w", err)
		}
	}

	if err := verifyState(ctx, controller, want, wantRoutes); err != nil {
		return err
	}
	fmt.Printf("verified pipeline and %d IPv4 routes\n", len(wantRoutes))
	return nil
}

func loadPipeline(p4infoPath, deviceConfigPath string) (*pipeline.Pipeline, error) {
	p4info, err := os.ReadFile(p4infoPath)
	if err != nil {
		return nil, fmt.Errorf("read P4Info %q: %w", p4infoPath, err)
	}
	deviceConfig, err := os.ReadFile(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read device configuration %q: %w", deviceConfigPath, err)
	}
	p, err := pipeline.LoadText(p4info, deviceConfig)
	if err != nil {
		return nil, fmt.Errorf("load pipeline: %w", err)
	}
	return p, nil
}

func buildRouteEntries(p *pipeline.Pipeline) ([]*p4v1.TableEntry, error) {
	entries := make([]*p4v1.TableEntry, 0, len(routes))
	for _, configured := range routes {
		prefix, err := codec.IPv4(configured.prefix)
		if err != nil {
			return nil, fmt.Errorf("encode route prefix %q: %w", configured.prefix, err)
		}
		port, err := codec.EncodeUint(configured.port, 9)
		if err != nil {
			return nil, fmt.Errorf("encode egress port %d: %w", configured.port, err)
		}
		srcMAC, err := codec.MAC(configured.srcMAC)
		if err != nil {
			return nil, fmt.Errorf("encode source MAC %q: %w", configured.srcMAC, err)
		}
		dstMAC, err := codec.MAC(configured.dstMAC)
		if err != nil {
			return nil, fmt.Errorf("encode destination MAC %q: %w", configured.dstMAC, err)
		}

		entry, err := tableentry.NewBuilder(p, routeTableName).
			Match("hdr.ipv4.dstAddr", tableentry.LPM(prefix, 24)).
			Action(
				"ipv4_forward",
				tableentry.Param("egress_port", port),
				tableentry.Param("src_mac", srcMAC),
				tableentry.Param("dst_mac", dstMAC),
			).
			Build()
		if err != nil {
			return nil, fmt.Errorf("build route %s/24: %w", configured.prefix, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func verifyState(
	ctx context.Context,
	controller *client.Client,
	want *pipeline.Pipeline,
	wantRoutes []*p4v1.TableEntry,
) error {
	got, err := controller.GetPipeline(ctx)
	if err != nil {
		return fmt.Errorf("read pipeline: %w", err)
	}
	if !proto.Equal(want.Info(), got.Info()) {
		return errors.New("pipeline P4Info readback does not match the requested pipeline")
	}
	if !bytes.Equal(want.DeviceConfig(), got.DeviceConfig()) {
		return errors.New("pipeline device configuration readback does not match")
	}

	table, ok := want.Table(routeTableName)
	if !ok {
		return fmt.Errorf("table %q not present in P4Info", routeTableName)
	}
	gotRoutes, err := controller.ReadTableEntries(ctx, table.ID)
	if err != nil {
		return fmt.Errorf("read IPv4 routes: %w", err)
	}
	if err := compareTableEntries(wantRoutes, gotRoutes); err != nil {
		return fmt.Errorf("verify IPv4 routes: %w", err)
	}
	return nil
}

func compareTableEntries(want, got []*p4v1.TableEntry) error {
	if len(want) != len(got) {
		return fmt.Errorf("entry count is %d, want %d", len(got), len(want))
	}
	wantKeys := make([]string, 0, len(want))
	gotKeys := make([]string, 0, len(got))
	for _, entry := range want {
		key, err := tableEntryKey(entry)
		if err != nil {
			return fmt.Errorf("encode expected entry: %w", err)
		}
		wantKeys = append(wantKeys, key)
	}
	for _, entry := range got {
		key, err := tableEntryKey(entry)
		if err != nil {
			return fmt.Errorf("encode read entry: %w", err)
		}
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(wantKeys)
	sort.Strings(gotKeys)
	for index := range wantKeys {
		if wantKeys[index] != gotKeys[index] {
			return fmt.Errorf("entry set differs at sorted position %d", index)
		}
	}
	return nil
}

func tableEntryKey(entry *p4v1.TableEntry) (string, error) {
	if entry == nil {
		return "", errors.New("nil table entry")
	}
	normalized := proto.Clone(entry).(*p4v1.TableEntry)
	sort.Slice(normalized.Match, func(i, j int) bool {
		return normalized.Match[i].GetFieldId() < normalized.Match[j].GetFieldId()
	})
	if action := normalized.GetAction().GetAction(); action != nil {
		sort.Slice(action.Params, func(i, j int) bool {
			return action.Params[i].GetParamId() < action.Params[j].GetParamId()
		})
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
