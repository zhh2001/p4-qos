package main

import (
	"bytes"
	"path/filepath"
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"google.golang.org/protobuf/proto"
)

func TestBuildRouteEntries(t *testing.T) {
	p, err := loadPipeline(
		filepath.Join("..", "build", "qos.p4info.txtpb"),
		filepath.Join("..", "build", "qos.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := buildRouteEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(routes) {
		t.Fatalf("built %d routes, want %d", len(entries), len(routes))
	}

	table, ok := p.Table(routeTableName)
	if !ok {
		t.Fatalf("missing table %q", routeTableName)
	}
	action, ok := p.Action("ipv4_forward")
	if !ok {
		t.Fatal("missing action ipv4_forward")
	}
	matchField, ok := table.MatchField("hdr.ipv4.dstAddr")
	if !ok {
		t.Fatal("missing IPv4 destination match field")
	}

	for index, entry := range entries {
		configured := routes[index]
		if entry.GetTableId() != table.ID {
			t.Errorf("route %s table ID is %d, want %d", configured.prefix, entry.GetTableId(), table.ID)
		}
		if len(entry.GetMatch()) != 1 {
			t.Fatalf("route %s has %d matches", configured.prefix, len(entry.GetMatch()))
		}
		match := entry.GetMatch()[0]
		if match.GetFieldId() != matchField.ID || match.GetLpm().GetPrefixLen() != 24 {
			t.Errorf("route %s has unexpected LPM match %v", configured.prefix, match)
		}
		prefix, err := codec.IPv4(configured.prefix)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(match.GetLpm().GetValue(), prefix) {
			t.Errorf("route %s match value is %x", configured.prefix, match.GetLpm().GetValue())
		}

		gotAction := entry.GetAction().GetAction()
		if gotAction == nil {
			t.Fatalf("route %s has no action", configured.prefix)
		}
		if gotAction.GetActionId() != action.ID {
			t.Errorf("route %s has unexpected action %v", configured.prefix, gotAction)
		}
		if len(gotAction.GetParams()) != 3 {
			t.Errorf("route %s has %d action parameters", configured.prefix, len(gotAction.GetParams()))
		}

		wantParams := map[string][]byte{
			"egress_port": codec.MustEncodeUint(configured.port, 9),
			"src_mac":     codec.MustMAC(configured.srcMAC),
			"dst_mac":     codec.MustMAC(configured.dstMAC),
		}
		gotParams := make(map[uint32][]byte, len(gotAction.GetParams()))
		for _, parameter := range gotAction.GetParams() {
			gotParams[parameter.GetParamId()] = parameter.GetValue()
		}
		for name, wantValue := range wantParams {
			definition, ok := action.Param(name)
			if !ok {
				t.Fatalf("action ipv4_forward has no parameter %q", name)
			}
			if !bytes.Equal(gotParams[definition.ID], wantValue) {
				t.Errorf(
					"route %s parameter %s is %x, want %x",
					configured.prefix,
					name,
					gotParams[definition.ID],
					wantValue,
				)
			}
		}
	}
}

func TestCompareTableEntriesIgnoresWireOrder(t *testing.T) {
	p, err := loadPipeline(
		filepath.Join("..", "build", "qos.p4info.txtpb"),
		filepath.Join("..", "build", "qos.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := buildRouteEntries(p)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]*p4v1.TableEntry, 0, len(want))
	for index := len(want) - 1; index >= 0; index-- {
		entry := proto.Clone(want[index]).(*p4v1.TableEntry)
		params := entry.GetAction().GetAction().Params
		for left, right := 0, len(params)-1; left < right; left, right = left+1, right-1 {
			params[left], params[right] = params[right], params[left]
		}
		got = append(got, entry)
	}
	if err := compareTableEntries(want, got); err != nil {
		t.Fatalf("equivalent route set rejected: %v", err)
	}

	got[0].GetAction().GetAction().Params[0].Value = []byte{0xff}
	if err := compareTableEntries(want, got); err == nil {
		t.Fatal("modified route set was accepted")
	}
	if err := compareTableEntries(want, got[:2]); err == nil {
		t.Fatal("incomplete route set was accepted")
	}
}
