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
	"github.com/zhh2001/p4runtime-go-controller/meter"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/protobuf/proto"
)

const (
	routeTableName      = "ipv4_lpm"
	classifierTableName = "qos_classifier"
	classMeterName      = "class_meter"

	classHigh      = 1
	classNormal    = 2
	classScavenger = 3
)

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

type classifierRule struct {
	name                 string
	ingressPort          uint64
	sourcePrefix         string
	destinationPrefix    string
	protocol             uint64
	destinationPort      uint64
	matchDestinationPort bool
	priority             int32
	classID              uint64
}

type classMeterConfig struct {
	classID int64
	config  meter.Config
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

var classifierRules = []classifierRule{
	{
		name:                 "high_https",
		ingressPort:          1,
		sourcePrefix:         "10.0.1.0",
		destinationPrefix:    "10.0.3.0",
		protocol:             6,
		destinationPort:      443,
		matchDestinationPort: true,
		priority:             30,
		classID:              classHigh,
	},
	{
		name:                 "normal_udp_5000",
		ingressPort:          2,
		sourcePrefix:         "10.0.2.0",
		destinationPrefix:    "10.0.3.0",
		protocol:             17,
		destinationPort:      5000,
		matchDestinationPort: true,
		priority:             30,
		classID:              classNormal,
	},
	{
		name:              "scavenger_udp",
		ingressPort:       2,
		sourcePrefix:      "10.0.2.0",
		destinationPrefix: "10.0.3.0",
		protocol:          17,
		priority:          10,
		classID:           classScavenger,
	},
}

var classMeters = []classMeterConfig{
	{
		classID: classHigh,
		config:  meter.Config{CIR: 10000, CBurst: 100, PIR: 20000, PBurst: 200},
	},
	{
		classID: classNormal,
		config:  meter.Config{CIR: 10000, CBurst: 100, PIR: 20000, PBurst: 200},
	},
	{
		classID: classScavenger,
		config:  meter.Config{CIR: 10000, CBurst: 100, PIR: 20000, PBurst: 200},
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
	wantClassifiers, err := buildClassifierEntries(want)
	if err != nil {
		return err
	}
	wantClassifierDefault, err := buildClassifierDefault(want)
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
	meterReader, err := meter.NewReader(controller, want)
	if err != nil {
		return fmt.Errorf("initialize meter access: %w", err)
	}

	if err := controller.BecomePrimary(ctx); err != nil {
		return fmt.Errorf("become primary: %w", err)
	}
	if !opts.verifyOnly {
		if _, err := controller.SetPipeline(ctx, want, client.SetPipelineOptions{}); err != nil {
			return fmt.Errorf("install pipeline: %w", err)
		}

		updates := make([]*p4v1.Update, 0, len(wantRoutes)+len(wantClassifiers))
		for _, entry := range wantRoutes {
			updates = append(updates, client.TableEntryUpdate(client.UpdateInsert, entry))
		}
		for _, entry := range wantClassifiers {
			updates = append(updates, client.TableEntryUpdate(client.UpdateInsert, entry))
		}
		if err := controller.Write(ctx, client.WriteOptions{}, updates...); err != nil {
			return fmt.Errorf("install table entries: %w", err)
		}
		for _, configured := range classMeters {
			if err := meterReader.Write(
				ctx,
				classMeterName,
				configured.classID,
				configured.config,
			); err != nil {
				return fmt.Errorf("configure class %d meter: %w", configured.classID, err)
			}
		}
	}

	if err := verifyState(
		ctx,
		controller,
		meterReader,
		want,
		wantRoutes,
		wantClassifiers,
		wantClassifierDefault,
	); err != nil {
		return err
	}
	fmt.Printf(
		"verified pipeline, %d IPv4 routes, %d QoS classifiers, and %d class meters\n",
		len(wantRoutes),
		len(wantClassifiers),
		len(classMeters),
	)
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

func buildClassifierEntries(p *pipeline.Pipeline) ([]*p4v1.TableEntry, error) {
	ingressMask, err := codec.EncodeUint(0x1ff, 9)
	if err != nil {
		return nil, fmt.Errorf("encode ingress-port mask: %w", err)
	}
	prefixMask, err := codec.TernaryMask(24, 32)
	if err != nil {
		return nil, fmt.Errorf("encode IPv4 prefix mask: %w", err)
	}
	protocolMask, err := codec.EncodeUint(0xff, 8)
	if err != nil {
		return nil, fmt.Errorf("encode protocol mask: %w", err)
	}
	destinationPortMask, err := codec.EncodeUint(0xffff, 16)
	if err != nil {
		return nil, fmt.Errorf("encode destination-port mask: %w", err)
	}

	entries := make([]*p4v1.TableEntry, 0, len(classifierRules))
	for _, configured := range classifierRules {
		ingressPort, err := codec.EncodeUint(configured.ingressPort, 9)
		if err != nil {
			return nil, fmt.Errorf("%s ingress port: %w", configured.name, err)
		}
		sourcePrefix, err := codec.IPv4(configured.sourcePrefix)
		if err != nil {
			return nil, fmt.Errorf("%s source prefix: %w", configured.name, err)
		}
		destinationPrefix, err := codec.IPv4(configured.destinationPrefix)
		if err != nil {
			return nil, fmt.Errorf("%s destination prefix: %w", configured.name, err)
		}
		protocol, err := codec.EncodeUint(configured.protocol, 8)
		if err != nil {
			return nil, fmt.Errorf("%s protocol: %w", configured.name, err)
		}
		classID, err := codec.EncodeUint(configured.classID, 8)
		if err != nil {
			return nil, fmt.Errorf("%s class ID: %w", configured.name, err)
		}

		builder := tableentry.NewBuilder(p, classifierTableName).
			Match(
				"standard_metadata.ingress_port",
				tableentry.Ternary(ingressPort, ingressMask),
			).
			Match(
				"hdr.ipv4.srcAddr",
				tableentry.Ternary(sourcePrefix, prefixMask),
			).
			Match(
				"hdr.ipv4.dstAddr",
				tableentry.Ternary(destinationPrefix, prefixMask),
			).
			Match(
				"hdr.ipv4.protocol",
				tableentry.Ternary(protocol, protocolMask),
			)
		if configured.matchDestinationPort {
			destinationPort, err := codec.EncodeUint(configured.destinationPort, 16)
			if err != nil {
				return nil, fmt.Errorf("%s destination port: %w", configured.name, err)
			}
			builder.Match(
				"meta.l4DstPort",
				tableentry.Ternary(destinationPort, destinationPortMask),
			)
		}

		entry, err := builder.
			Action(
				"set_qos_class",
				tableentry.Param("class_id", classID),
			).
			Priority(configured.priority).
			Build()
		if err != nil {
			return nil, fmt.Errorf("build classifier %s: %w", configured.name, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func buildClassifierDefault(p *pipeline.Pipeline) (*p4v1.TableEntry, error) {
	classID, err := codec.EncodeUint(classNormal, 8)
	if err != nil {
		return nil, fmt.Errorf("encode default class ID: %w", err)
	}
	entry, err := tableentry.NewBuilder(p, classifierTableName).
		AsDefault().
		Action(
			"set_qos_class",
			tableentry.Param("class_id", classID),
		).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build classifier default: %w", err)
	}
	return entry, nil
}

func verifyState(
	ctx context.Context,
	controller *client.Client,
	meterReader *meter.Reader,
	want *pipeline.Pipeline,
	wantRoutes []*p4v1.TableEntry,
	wantClassifiers []*p4v1.TableEntry,
	wantClassifierDefault *p4v1.TableEntry,
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

	if err := verifyTableEntries(
		ctx,
		controller,
		want,
		routeTableName,
		wantRoutes,
	); err != nil {
		return fmt.Errorf("verify IPv4 routes: %w", err)
	}
	if err := verifyTableEntries(
		ctx,
		controller,
		want,
		classifierTableName,
		wantClassifiers,
	); err != nil {
		return fmt.Errorf("verify QoS classifiers: %w", err)
	}
	if err := verifyDefaultTableEntry(
		ctx,
		controller,
		want,
		classifierTableName,
		wantClassifierDefault,
	); err != nil {
		return fmt.Errorf("verify classifier default: %w", err)
	}
	if err := verifyClassMeters(ctx, meterReader, want); err != nil {
		return fmt.Errorf("verify class meters: %w", err)
	}
	return nil
}

func verifyDefaultTableEntry(
	ctx context.Context,
	controller *client.Client,
	p *pipeline.Pipeline,
	tableName string,
	want *p4v1.TableEntry,
) error {
	table, ok := p.Table(tableName)
	if !ok {
		return fmt.Errorf("table %q not present in P4Info", tableName)
	}
	entities, err := controller.Read(ctx, &p4v1.Entity{
		Entity: &p4v1.Entity_TableEntry{TableEntry: &p4v1.TableEntry{
			TableId:         table.ID,
			IsDefaultAction: true,
		}},
	})
	if err != nil {
		return fmt.Errorf("read table %q default: %w", tableName, err)
	}
	if len(entities) != 1 {
		return fmt.Errorf(
			"table %q default read returned %d entities, want 1",
			tableName,
			len(entities),
		)
	}
	if entities[0].GetTableEntry() == nil {
		return fmt.Errorf("table %q default read returned a non-table entity", tableName)
	}
	return compareTableEntries(
		[]*p4v1.TableEntry{want},
		[]*p4v1.TableEntry{entities[0].GetTableEntry()},
	)
}

func verifyTableEntries(
	ctx context.Context,
	controller *client.Client,
	p *pipeline.Pipeline,
	tableName string,
	want []*p4v1.TableEntry,
) error {
	table, ok := p.Table(tableName)
	if !ok {
		return fmt.Errorf("table %q not present in P4Info", tableName)
	}
	got, err := controller.ReadTableEntries(ctx, table.ID)
	if err != nil {
		return fmt.Errorf("read table %q: %w", tableName, err)
	}
	if err := compareTableEntries(want, got); err != nil {
		return err
	}
	return nil
}

func verifyClassMeters(
	ctx context.Context,
	meterReader *meter.Reader,
	p *pipeline.Pipeline,
) error {
	definition, ok := p.Meter(classMeterName)
	if !ok {
		return fmt.Errorf("meter %q not present in P4Info", classMeterName)
	}
	for _, configured := range classMeters {
		entries, err := meterReader.Read(ctx, classMeterName, configured.classID)
		if err != nil {
			return fmt.Errorf("read class %d meter: %w", configured.classID, err)
		}
		if len(entries) != 1 {
			return fmt.Errorf(
				"class %d meter read returned %d entries, want 1",
				configured.classID,
				len(entries),
			)
		}
		entry := entries[0]
		if entry.GetMeterId() != definition.ID ||
			entry.GetIndex().GetIndex() != configured.classID {
			return fmt.Errorf("class %d meter identity does not match", configured.classID)
		}
		wantConfig := &p4v1.MeterConfig{
			Cir:    configured.config.CIR,
			Cburst: configured.config.CBurst,
			Pir:    configured.config.PIR,
			Pburst: configured.config.PBurst,
		}
		if !proto.Equal(entry.GetConfig(), wantConfig) {
			return fmt.Errorf("class %d meter configuration does not match", configured.classID)
		}
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
