import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P4INFO_PATH = ROOT / "build" / "qos.p4info.txtpb"
BMV2_JSON_PATH = ROOT / "build" / "qos.json"


def _textproto_blocks(text, field):
    opening = f"{field} {{"
    blocks = []
    lines = text.splitlines()
    for start, line in enumerate(lines):
        if line.strip() != opening:
            continue
        depth = 0
        for end in range(start, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                blocks.append("\n".join(lines[start : end + 1]))
                break
        else:
            raise AssertionError(f"unterminated {field} block in P4Info")
    return blocks


def _textproto_scalar(block, field):
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*([^\s]+)", block)
    return match.group(1).strip('"') if match else None


def _textproto_bytes(block, field):
    match = re.search(rf'(?m)^\s*{re.escape(field)}:\s*("(?:[^"\\]|\\.)*")', block)
    if not match:
        return None
    return ast.literal_eval(match.group(1)).encode("latin1")


def _entity_by_alias(text, field):
    entities = {}
    for block in _textproto_blocks(text, field):
        preambles = _textproto_blocks(block, "preamble")
        if len(preambles) != 1:
            raise AssertionError(f"{field} entry has {len(preambles)} preambles")
        alias = _textproto_scalar(preambles[0], "alias")
        if not alias:
            raise AssertionError(f"{field} entry has no alias")
        entities[alias] = block
    return entities


def _normalized(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _walk_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _field_paths(value):
    return [
        tuple(item["value"])
        for item in _walk_json(value)
        if isinstance(item, dict)
        and item.get("type") == "field"
        and isinstance(item.get("value"), list)
    ]


def _integer_literals(value):
    literals = []
    for item in _walk_json(value):
        if not isinstance(item, dict) or item.get("type") != "hexstr":
            continue
        try:
            literals.append(int(item["value"], 0))
        except (KeyError, TypeError, ValueError):
            continue
    return literals


class GeneratedPipelineStructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [
            str(path.relative_to(ROOT))
            for path in (P4INFO_PATH, BMV2_JSON_PATH)
            if not path.is_file()
        ]
        if missing:
            raise AssertionError(
                f"missing generated artifacts {missing}; run 'make build' first"
            )
        cls.p4info = P4INFO_PATH.read_text(encoding="utf-8")
        try:
            cls.bmv2 = json.loads(BMV2_JSON_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise AssertionError(f"invalid BMv2 JSON: {error}") from error

    def test_p4info_tables_and_match_keys(self):
        tables = _entity_by_alias(self.p4info, "tables")
        self.assertTrue(
            {"qos_classifier", "ipv4_lpm"}.issubset(tables),
            f"P4Info tables are {sorted(tables)}",
        )

        classifier_fields = {}
        for block in _textproto_blocks(tables["qos_classifier"], "match_fields"):
            name = _textproto_scalar(block, "name")
            classifier_fields[_normalized(name)] = _textproto_scalar(
                block, "match_type"
            )
        expected_classifier_fields = {
            "standardmetadataingressport",
            "hdripv4srcaddr",
            "hdripv4dstaddr",
            "hdripv4protocol",
            "metal4srcport",
            "metal4dstport",
        }
        self.assertEqual(
            set(classifier_fields),
            expected_classifier_fields,
            f"qos_classifier fields are {sorted(classifier_fields)}",
        )
        self.assertEqual(
            set(classifier_fields.values()),
            {"TERNARY"},
            f"qos_classifier match types are {classifier_fields}",
        )

        route_fields = {}
        for block in _textproto_blocks(tables["ipv4_lpm"], "match_fields"):
            name = _textproto_scalar(block, "name")
            route_fields[_normalized(name)] = _textproto_scalar(block, "match_type")
        self.assertEqual(
            route_fields,
            {"hdripv4dstaddr": "LPM"},
            f"ipv4_lpm fields are {route_fields}",
        )

    def test_p4info_actions_and_table_references(self):
        actions = _entity_by_alias(self.p4info, "actions")
        expected = {"set_qos_class", "ipv4_forward", "drop"}
        self.assertTrue(
            expected.issubset(actions),
            f"P4Info actions are {sorted(actions)}",
        )

        action_ids = {}
        for alias, block in actions.items():
            preamble = _textproto_blocks(block, "preamble")[0]
            action_ids[alias] = int(_textproto_scalar(preamble, "id"))

        tables = _entity_by_alias(self.p4info, "tables")
        classifier_refs = {
            int(_textproto_scalar(block, "id"))
            for block in _textproto_blocks(tables["qos_classifier"], "action_refs")
        }
        route_refs = {
            int(_textproto_scalar(block, "id"))
            for block in _textproto_blocks(tables["ipv4_lpm"], "action_refs")
        }
        self.assertIn(
            action_ids["set_qos_class"],
            classifier_refs,
            "qos_classifier cannot invoke set_qos_class",
        )
        self.assertTrue(
            {action_ids["ipv4_forward"], action_ids["drop"]}.issubset(route_refs),
            "ipv4_lpm does not expose both forwarding and drop actions",
        )

        classifier_default = _textproto_blocks(
            tables["qos_classifier"], "initial_default_action"
        )
        self.assertEqual(
            len(classifier_default), 1, "qos_classifier has no initial default"
        )
        self.assertEqual(
            int(_textproto_scalar(classifier_default[0], "action_id")),
            action_ids["set_qos_class"],
            "qos_classifier default does not select a QoS class",
        )
        default_arguments = _textproto_blocks(classifier_default[0], "arguments")
        self.assertEqual(
            len(default_arguments), 1, "qos_classifier default must set one class"
        )
        self.assertEqual(
            _textproto_bytes(default_arguments[0], "value"),
            b"\x02",
            "qos_classifier miss does not default to NORMAL class 2",
        )
        self.assertIsNone(
            _textproto_scalar(tables["qos_classifier"], "const_default_action_id"),
            "qos_classifier default must remain P4Runtime configurable",
        )

        route_default = _textproto_blocks(tables["ipv4_lpm"], "initial_default_action")
        self.assertEqual(len(route_default), 1, "ipv4_lpm has no initial default")
        self.assertEqual(
            int(_textproto_scalar(route_default[0], "action_id")),
            action_ids["drop"],
            "ipv4_lpm route miss does not default to drop",
        )

    def test_p4info_packet_meter(self):
        meters = _entity_by_alias(self.p4info, "meters")
        self.assertEqual(
            set(meters),
            {"class_meter"},
            f"P4Info meters are {sorted(meters)}",
        )
        meter = meters["class_meter"]
        specs = _textproto_blocks(meter, "spec")
        self.assertEqual(len(specs), 1, "class_meter must have one MeterSpec")
        self.assertEqual(
            _textproto_scalar(specs[0], "unit"),
            "PACKETS",
            "class_meter is not packet based",
        )
        self.assertEqual(
            int(_textproto_scalar(meter, "size")),
            4,
            "class_meter must have four indexed entries",
        )
        self.assertFalse(
            _textproto_blocks(self.p4info, "direct_meters"),
            "class_meter must be an indirect meter",
        )

    def test_bmv2_indirect_meter_uses_class_index(self):
        meters = self.bmv2.get("meter_arrays", [])
        self.assertEqual(
            len(meters), 1, f"expected one BMv2 meter array, found {len(meters)}"
        )
        meter = meters[0]
        self.assertTrue(
            meter.get("name", "").endswith(".class_meter"),
            f"unexpected meter name {meter.get('name')!r}",
        )
        self.assertIs(meter.get("is_direct"), False, "class_meter is direct")
        self.assertEqual(meter.get("size"), 4, "class_meter JSON size is not four")
        self.assertEqual(
            meter.get("type"), "packets", "class_meter JSON unit is not packets"
        )

        executions = []
        for action in self.bmv2.get("actions", []):
            for position, primitive in enumerate(action.get("primitives", [])):
                if primitive.get("op") == "execute_meter":
                    executions.append((action, position, primitive))
        self.assertEqual(
            len(executions),
            1,
            f"expected one execute_meter primitive, found {len(executions)}",
        )
        action, position, execution = executions[0]
        parameters = execution.get("parameters", [])
        self.assertEqual(
            len(parameters), 3, f"execute_meter parameters are {parameters}"
        )
        self.assertEqual(
            parameters[0],
            {"type": "meter_array", "value": meter["name"]},
            "execute_meter does not reference class_meter",
        )
        self.assertEqual(
            parameters[1].get("type"), "field", "meter index is not a field"
        )
        self.assertEqual(
            parameters[2].get("type"), "field", "meter result is not a field"
        )
        self.assertTrue(
            _normalized(parameters[2]["value"][-1]).endswith("metercolor"),
            f"meter result target is {parameters[2]['value']}",
        )

        index_path = tuple(parameters[1]["value"])
        index_uses_class = _normalized(index_path[-1]).endswith("qosclass")
        if not index_uses_class:
            class_index_assignments = []
            for primitive in action.get("primitives", [])[:position]:
                primitive_parameters = primitive.get("parameters", [])
                if (
                    primitive.get("op") == "assign"
                    and primitive_parameters
                    and tuple(primitive_parameters[0].get("value", [])) == index_path
                ):
                    class_index_assignments.extend(
                        _field_paths(primitive_parameters[1:])
                    )
            index_uses_class = any(
                _normalized(path[-1]).endswith("qosclass")
                for path in class_index_assignments
            )
        self.assertTrue(
            index_uses_class,
            f"meter index {index_path} is not derived from the QoS class",
        )

    def test_bmv2_dscp_and_red_policy(self):
        actions = self.bmv2.get("actions", [])
        dscp_values = set()
        ecn_writes = []
        drop_actions = set()
        for action in actions:
            for primitive in action.get("primitives", []):
                if primitive.get("op") == "mark_to_drop":
                    drop_actions.add(action["name"])
                parameters = primitive.get("parameters", [])
                if primitive.get("op") != "assign" or not parameters:
                    continue
                target = parameters[0]
                if target.get("type") != "field":
                    continue
                leaf = _normalized(target["value"][-1])
                if leaf == "dscp":
                    dscp_values.update(_integer_literals(parameters[1:]))
                elif leaf == "ecn":
                    ecn_writes.append(action["name"])
        self.assertEqual(
            dscp_values,
            {0, 8, 10, 46},
            f"compiled DSCP assignments are {sorted(dscp_values)}",
        )
        self.assertFalse(ecn_writes, f"QoS actions write ECN in {ecn_writes}")
        self.assertTrue(drop_actions, "BMv2 JSON has no mark_to_drop action")

        ingress = next(
            (
                pipeline
                for pipeline in self.bmv2.get("pipelines", [])
                if pipeline.get("name") == "ingress"
            ),
            None,
        )
        self.assertIsNotNone(ingress, "BMv2 JSON has no ingress pipeline")
        red_conditions = []
        for condition in ingress.get("conditionals", []):
            expression = condition.get("expression", {})
            while (
                isinstance(expression, dict)
                and expression.get("type") == "expression"
                and isinstance(expression.get("value"), dict)
            ):
                expression = expression["value"]
            fields = {_normalized(path[-1]) for path in _field_paths(expression)}
            if (
                expression.get("op") == "=="
                and any(field.endswith("metercolor") for field in fields)
                and 2 in _integer_literals(expression)
            ):
                red_conditions.append(condition)
        self.assertEqual(
            len(red_conditions),
            1,
            f"expected one meter-color RED comparison, found {len(red_conditions)}",
        )

        true_target = red_conditions[0].get("true_next")
        tables = {table["name"]: table for table in ingress.get("tables", [])}
        red_table = tables.get(true_target)
        self.assertIsNotNone(
            red_table, f"RED true branch targets missing table {true_target!r}"
        )
        target_actions = set(red_table.get("actions", []))
        self.assertTrue(
            target_actions and target_actions.issubset(drop_actions),
            f"RED true branch {true_target!r} is not drop-only: {target_actions}",
        )

        successors = {
            successor
            for successor in [
                red_table.get("base_default_next"),
                *red_table.get("next_tables", {}).values(),
            ]
            if successor is not None
        }
        self.assertTrue(successors, "RED drop table has no terminating successor")
        actions_by_name = {}
        for action in self.bmv2.get("actions", []):
            actions_by_name.setdefault(action["name"], []).append(action)
        for successor in successors:
            self.assertNotEqual(
                successor,
                "MyIngress.ipv4_lpm",
                "RED drop path continues into IPv4 forwarding",
            )
            successor_table = tables.get(successor)
            self.assertIsNotNone(
                successor_table, f"RED drop successor table {successor!r} is missing"
            )
            successor_actions = successor_table.get("actions", [])
            self.assertTrue(
                successor_actions,
                f"RED drop successor {successor!r} has no terminating action",
            )
            for action_name in successor_actions:
                action_variants = actions_by_name.get(action_name, [])
                self.assertTrue(
                    action_variants
                    and all(
                        any(
                            primitive.get("op") == "exit"
                            for primitive in action.get("primitives", [])
                        )
                        for action in action_variants
                    ),
                    f"RED successor action {action_name!r} does not exit ingress",
                )

    def test_bmv2_ttl_and_ipv4_checksums(self):
        ttl_updates = []
        for action in self.bmv2.get("actions", []):
            for primitive in action.get("primitives", []):
                parameters = primitive.get("parameters", [])
                if not parameters or parameters[0].get("type") != "field":
                    continue
                if _normalized(parameters[0]["value"][-1]) == "ttl":
                    ttl_updates.append(primitive)
        self.assertEqual(
            len(ttl_updates), 1, f"expected one TTL update, found {len(ttl_updates)}"
        )
        ttl_update = ttl_updates[0]
        self.assertEqual(
            ttl_update.get("op"), "assign", "TTL update is not an assignment"
        )
        self.assertTrue(
            any(_normalized(path[-1]) == "ttl" for path in _field_paths(ttl_update)),
            "TTL update does not use the incoming TTL",
        )
        operators = {
            item["op"]
            for item in _walk_json(ttl_update)
            if isinstance(item, dict) and isinstance(item.get("op"), str)
        }
        literals = set(_integer_literals(ttl_update))
        self.assertTrue(
            ("-" in operators and 1 in literals)
            or ("+" in operators and 0xFF in literals),
            f"TTL update is not a one-step decrement: ops={operators}, values={literals}",
        )

        checksums = self.bmv2.get("checksums", [])
        calculations = {
            calculation["name"]: calculation
            for calculation in self.bmv2.get("calculations", [])
        }
        required_fields = {
            "ipv4version",
            "ipv4ihl",
            "ipv4dscp",
            "ipv4ecn",
            "ipv4totallen",
            "ipv4identification",
            "ipv4flags",
            "ipv4fragoffset",
            "ipv4ttl",
            "ipv4protocol",
            "ipv4srcaddr",
            "ipv4dstaddr",
        }
        for mode in ("verify", "update"):
            candidates = [
                checksum
                for checksum in checksums
                if checksum.get(mode) is True
                and [_normalized(part) for part in checksum.get("target", [])]
                == ["ipv4", "hdrchecksum"]
            ]
            self.assertEqual(
                len(candidates),
                1,
                f"expected one IPv4 checksum {mode} entry, found {len(candidates)}",
            )
            calculation = calculations.get(candidates[0].get("calculation"))
            self.assertIsNotNone(calculation, f"checksum {mode} calculation is missing")
            self.assertEqual(
                calculation.get("algo"),
                "csum16",
                f"checksum {mode} does not use csum16",
            )
            fields = {
                _normalized(".".join(path))
                for path in _field_paths(calculation.get("input", []))
            }
            self.assertEqual(
                fields,
                required_fields,
                f"checksum {mode} fields are {sorted(fields)}",
            )


if __name__ == "__main__":
    unittest.main()
