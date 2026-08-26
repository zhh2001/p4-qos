package main

import (
	"bytes"
	"path/filepath"
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/meter"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/protobuf/proto"
)

func loadTestPipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	p, err := loadPipeline(
		filepath.Join("..", "build", "qos.p4info.txtpb"),
		filepath.Join("..", "build", "qos.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildRouteEntries(t *testing.T) {
	p := loadTestPipeline(t)
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

func TestBuildClassifierEntries(t *testing.T) {
	p := loadTestPipeline(t)
	entries, err := buildClassifierEntries(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(classifierRules) {
		t.Fatalf("built %d classifiers, want %d", len(entries), len(classifierRules))
	}

	table, ok := p.Table(classifierTableName)
	if !ok {
		t.Fatalf("missing table %q", classifierTableName)
	}
	action, ok := p.Action("set_qos_class")
	if !ok {
		t.Fatal("missing action set_qos_class")
	}
	classParameter, ok := action.Param("class_id")
	if !ok {
		t.Fatal("action set_qos_class has no class_id parameter")
	}

	prefixMask, err := codec.TernaryMask(24, 32)
	if err != nil {
		t.Fatal(err)
	}
	for index, entry := range entries {
		configured := classifierRules[index]
		if entry.GetTableId() != table.ID {
			t.Errorf(
				"classifier %s table ID is %d, want %d",
				configured.name,
				entry.GetTableId(),
				table.ID,
			)
		}
		if entry.GetPriority() != configured.priority {
			t.Errorf(
				"classifier %s priority is %d, want %d",
				configured.name,
				entry.GetPriority(),
				configured.priority,
			)
		}

		wantMatchCount := 4
		if configured.matchDestinationPort {
			wantMatchCount++
		}
		if len(entry.GetMatch()) != wantMatchCount {
			t.Fatalf(
				"classifier %s has %d matches, want %d",
				configured.name,
				len(entry.GetMatch()),
				wantMatchCount,
			)
		}
		matches := make(map[uint32]*p4v1.FieldMatch, len(entry.GetMatch()))
		for _, match := range entry.GetMatch() {
			if matches[match.GetFieldId()] != nil {
				t.Fatalf("classifier %s repeats field ID %d", configured.name, match.GetFieldId())
			}
			matches[match.GetFieldId()] = match
		}
		assertTernary := func(field string, value, mask []byte) {
			t.Helper()
			definition, ok := table.MatchField(field)
			if !ok {
				t.Fatalf("table %s has no field %q", classifierTableName, field)
			}
			match := matches[definition.ID]
			if match == nil {
				t.Fatalf("classifier %s has no match for %s", configured.name, field)
			}
			if !bytes.Equal(match.GetTernary().GetValue(), value) ||
				!bytes.Equal(match.GetTernary().GetMask(), mask) {
				t.Errorf(
					"classifier %s match %s is %x/%x, want %x/%x",
					configured.name,
					field,
					match.GetTernary().GetValue(),
					match.GetTernary().GetMask(),
					value,
					mask,
				)
			}
		}
		assertTernary(
			"standard_metadata.ingress_port",
			codec.MustEncodeUint(configured.ingressPort, 9),
			codec.MustEncodeUint(0x1ff, 9),
		)
		assertTernary(
			"hdr.ipv4.srcAddr",
			codec.MustIPv4(configured.sourcePrefix),
			prefixMask,
		)
		assertTernary(
			"hdr.ipv4.dstAddr",
			codec.MustIPv4(configured.destinationPrefix),
			prefixMask,
		)
		assertTernary(
			"hdr.ipv4.protocol",
			codec.MustEncodeUint(configured.protocol, 8),
			codec.MustEncodeUint(0xff, 8),
		)
		if configured.matchDestinationPort {
			assertTernary(
				"meta.l4DstPort",
				codec.MustEncodeUint(configured.destinationPort, 16),
				codec.MustEncodeUint(0xffff, 16),
			)
		}

		gotAction := entry.GetAction().GetAction()
		if gotAction == nil || gotAction.GetActionId() != action.ID {
			t.Fatalf("classifier %s has unexpected action %v", configured.name, gotAction)
		}
		if len(gotAction.GetParams()) != 1 ||
			gotAction.GetParams()[0].GetParamId() != classParameter.ID ||
			!bytes.Equal(
				gotAction.GetParams()[0].GetValue(),
				codec.MustEncodeUint(configured.classID, 8),
			) {
			t.Errorf("classifier %s has unexpected class action %v", configured.name, gotAction)
		}
	}
}

func TestBuildClassifierDefault(t *testing.T) {
	p := loadTestPipeline(t)
	entry, err := buildClassifierDefault(p)
	if err != nil {
		t.Fatal(err)
	}
	table, ok := p.Table(classifierTableName)
	if !ok {
		t.Fatalf("missing table %q", classifierTableName)
	}
	action, ok := p.Action("set_qos_class")
	if !ok {
		t.Fatal("missing action set_qos_class")
	}
	classParameter, ok := action.Param("class_id")
	if !ok {
		t.Fatal("action set_qos_class has no class_id parameter")
	}

	if entry.GetTableId() != table.ID || !entry.GetIsDefaultAction() {
		t.Fatalf("unexpected classifier default identity %v", entry)
	}
	if len(entry.GetMatch()) != 0 || entry.GetPriority() != 0 {
		t.Errorf("classifier default has matches or priority: %v", entry)
	}
	gotAction := entry.GetAction().GetAction()
	if gotAction == nil || gotAction.GetActionId() != action.ID ||
		len(gotAction.GetParams()) != 1 ||
		gotAction.GetParams()[0].GetParamId() != classParameter.ID ||
		!bytes.Equal(
			gotAction.GetParams()[0].GetValue(),
			codec.MustEncodeUint(classNormal, 8),
		) {
		t.Errorf("unexpected classifier default action %v", gotAction)
	}
}

func TestClassMeterConfiguration(t *testing.T) {
	p := loadTestPipeline(t)
	definition, ok := p.Meter(classMeterName)
	if !ok {
		t.Fatalf("missing meter %q", classMeterName)
	}
	wantClasses := map[int64]bool{
		classHigh:      true,
		classNormal:    true,
		classScavenger: true,
	}
	wantConfig := meter.Config{
		CIR:    5,
		CBurst: 2,
		PIR:    10,
		PBurst: 4,
	}
	if len(classMeters) != len(wantClasses) {
		t.Fatalf("configured %d class meters, want %d", len(classMeters), len(wantClasses))
	}
	for _, configured := range classMeters {
		if !wantClasses[configured.classID] {
			t.Errorf("unexpected or duplicate class meter index %d", configured.classID)
		}
		delete(wantClasses, configured.classID)
		if configured.classID < 0 || configured.classID >= definition.Size {
			t.Errorf("class meter index %d is outside size %d", configured.classID, definition.Size)
		}
		if configured.config != wantConfig {
			t.Errorf(
				"class %d meter configuration is %+v, want %+v",
				configured.classID,
				configured.config,
				wantConfig,
			)
		}
	}
	if len(wantClasses) != 0 {
		t.Errorf("missing class meter indexes %v", wantClasses)
	}
}

func TestCompareTableEntriesIgnoresWireOrder(t *testing.T) {
	p := loadTestPipeline(t)
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
