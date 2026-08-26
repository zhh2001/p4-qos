import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import ICMP, Ether, IP, IPOption, Raw, TCP, UDP


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from qos_topology import (  # noqa: E402
    DEFAULT_THRIFT_PORT,
    HOSTS,
    QosNetwork,
)


CONTROLLER = ROOT / "build" / "qos-controller"
P4INFO = ROOT / "build" / "qos.p4info.txtpb"
DEVICE_CONFIG = ROOT / "build" / "qos.json"
PACKET_OUTGOING = 4
ETH_P_ALL = 0x0003
ETHERNET_HEADER_LENGTH = 14
IPV4_HEADER_LENGTH = 20
CAPTURE_SECONDS = 0.35
METER_CIR = 5
METER_COMMITTED_BURST = 2
METER_PIR = 10
METER_PEAK_BURST = 4
METER_REFILL_SECONDS = (
    max(
        METER_COMMITTED_BURST / METER_CIR,
        METER_PEAK_BURST / METER_PIR,
    )
    + 0.1
)
METER_BURST_PACKETS = 8

SEND_FRAMES = """
import socket
import sys

frames = [bytes.fromhex(value) for value in sys.argv[2:]]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
    sender.bind((sys.argv[1], 0))
    for frame in frames:
        written = sender.send(frame)
        if written != len(frame):
            raise SystemExit(f"sent {written} of {len(frame)} bytes")
"""


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def transport_checksum(ip_packet):
    header_length = ip_packet.ihl * 4
    segment_length = ip_packet.len - header_length
    segment = bytes(ip_packet.payload)[:segment_length]
    pseudo_header = (
        socket.inet_aton(ip_packet.src)
        + socket.inet_aton(ip_packet.dst)
        + bytes((0, ip_packet.proto))
        + struct.pack("!H", segment_length)
    )
    return checksum(pseudo_header + segment)


def serialized(packet):
    return Ether(bytes(packet))


def with_ipv4_total_length(frame, total_length):
    result = bytearray(frame)
    struct.pack_into("!H", result, ETHERNET_HEADER_LENGTH + 2, total_length)
    checksum_offset = ETHERNET_HEADER_LENGTH + 10
    struct.pack_into("!H", result, checksum_offset, 0)
    header = bytes(
        result[ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH]
    )
    struct.pack_into("!H", result, checksum_offset, checksum(header))
    return bytes(result)


def meter_packet(qos_class, token, sequence):
    if qos_class == "HIGH":
        source = "h1"
        transport = TCP(
            sport=40000 + sequence,
            dport=443,
            seq=0x71000000 + sequence,
            ack=0x72000000 + sequence,
            flags="PA",
        )
        ip_source = "10.0.1.1"
    elif qos_class == "NORMAL":
        source = "h2"
        transport = UDP(sport=40000 + sequence, dport=5000)
        ip_source = "10.0.2.1"
    else:
        raise ValueError(f"unsupported metered class {qos_class!r}")

    packet = (
        Ether(src=HOSTS[source]["mac"], dst=HOSTS[source]["gateway_mac"])
        / IP(
            src=ip_source,
            dst="10.0.3.200",
            ttl=64,
            id=0x6000 + sequence,
            tos=(31 << 2) | (sequence % 4),
        )
        / transport
        / Raw(token)
    )
    return source, serialized(packet)


def open_captures():
    captures = {}
    try:
        for port in range(1, 4):
            capture = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
            captures[port] = capture
            capture.bind((f"s1-eth{port}", 0))
            capture.setblocking(False)
    except BaseException:
        for capture in captures.values():
            capture.close()
        raise
    return captures


def send_frames(host, interface, frames):
    if not frames:
        raise ValueError("at least one frame is required")
    sender = host.popen(
        [sys.executable, "-c", SEND_FRAMES, interface]
        + [frame.hex() for frame in frames],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = sender.communicate(timeout=3)
    except subprocess.TimeoutExpired as error:
        sender.terminate()
        try:
            sender.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            sender.kill()
            sender.communicate()
        raise AssertionError(f"raw sender on {host.name} timed out") from error
    if sender.returncode != 0:
        detail = stderr.decode().strip() or stdout.decode().strip()
        raise AssertionError(
            f"raw sender on {host.name} exited with status "
            f"{sender.returncode}: {detail}"
        )


def capture_batches(lab, batches, tokens):
    tokens = tuple(tokens)
    if not tokens:
        raise ValueError("at least one token is required")
    captures = open_captures()
    observed = {port: [] for port in captures}
    try:
        for source, frames in batches:
            send_frames(lab.net.get(source), f"{source}-eth0", frames)
        deadline = time.monotonic() + CAPTURE_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select(list(captures.values()), [], [], remaining)
            if not ready:
                break
            for capture in ready:
                while True:
                    try:
                        packet, address = capture.recvfrom(65535)
                    except BlockingIOError:
                        break
                    if address[2] != PACKET_OUTGOING or not any(
                        token in packet for token in tokens
                    ):
                        continue
                    port = next(
                        number
                        for number, candidate in captures.items()
                        if candidate is capture
                    )
                    observed[port].append(packet)
    finally:
        for capture in captures.values():
            capture.close()
    return observed


def capture_token(lab, source, frame, token):
    return capture_batches(lab, ((source, (frame,)),), (token,))


def observations_text(observed):
    parts = []
    for port, packets in observed.items():
        summaries = [Ether(packet).summary() for packet in packets]
        parts.append(f"port {port}: {summaries}")
    return "; ".join(parts)


def data_observations(observed):
    data = {port: [] for port in observed}
    for port, packets in observed.items():
        for packet in packets:
            candidate = Ether(packet)
            if candidate.haslayer(ICMP) and candidate[ICMP].type == 3:
                continue
            data[port].append(packet)
    return data


def data_observations_by_token(observed, tokens):
    tokens = tuple(tokens)
    by_token = {token: {port: [] for port in observed} for token in tokens}
    for port, packets in data_observations(observed).items():
        for packet in packets:
            for token in tokens:
                if token in packet:
                    by_token[token][port].append(packet)
    return by_token


def lab_cleanup_errors(lab, node_pids):
    errors = []
    if lab.switch.process.poll() is None:
        errors.append(f"owned process {lab.switch.process.pid} is still running")
    for pid in node_pids:
        if Path(f"/proc/{pid}").exists():
            errors.append(f"Mininet process {pid} remains")
    for interface in (
        "h1-eth0",
        "h2-eth0",
        "h3-eth0",
        "s1-eth1",
        "s1-eth2",
        "s1-eth3",
    ):
        try:
            socket.if_nametoindex(interface)
        except OSError:
            pass
        else:
            errors.append(f"interface {interface} still exists")
    if lab.runtime_path.exists():
        errors.append(f"runtime path {lab.runtime_path} remains")
    for host, port in (
        ("127.0.0.1", 50051),
        ("0.0.0.0", DEFAULT_THRIFT_PORT),
    ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((host, port))
            except OSError as error:
                errors.append(f"TCP port {host}:{port} was not released: {error}")
    return errors


def assert_lab_clean(test, lab, node_pids):
    errors = lab_cleanup_errors(lab, node_pids)
    test.assertFalse(errors, "; ".join(errors))


@unittest.skipUnless(os.geteuid() == 0, "Mininet integration tests require root")
class ForwardingIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = QosNetwork()
        cls.lab.__enter__()
        try:
            cls.lab.program(CONTROLLER, P4INFO, DEVICE_CONFIG)
            cls.lab.program(CONTROLLER, P4INFO, DEVICE_CONFIG, verify_only=True)
        except Exception:
            cls.lab.close()
            raise

    @classmethod
    def tearDownClass(cls):
        node_pids = [node.pid for node in cls.lab.net.hosts + cls.lab.net.switches]
        cls.lab.close()
        errors = lab_cleanup_errors(cls.lab, node_pids)
        if errors:
            raise AssertionError("; ".join(errors))

    def assert_forwarded(
        self,
        source,
        packet,
        token,
        expected_port,
        qos_class,
        expected_dscp,
    ):
        sent = serialized(packet)
        observed = capture_token(self.lab, source, bytes(sent), token)
        data = data_observations(observed)
        count = sum(len(packets) for packets in data.values())
        expected_ecn = sent[IP].tos & 0x03
        context = (
            f"token {token!r}, class {qos_class}, expected GREEN DSCP "
            f"{expected_dscp}, expected ECN {expected_ecn}"
        )
        self.assertEqual(
            count,
            1,
            f"{context}: produced {count} egress packets; "
            f"{observations_text(observed)}",
        )
        self.assertEqual(
            len(data[expected_port]),
            1,
            f"{context}: did not use port {expected_port}; "
            f"{observations_text(observed)}",
        )
        received = Ether(data[expected_port][0])
        self.assert_packet_integrity(
            sent,
            received,
            token,
            expected_port,
            qos_class,
            "GREEN",
            expected_dscp,
        )

    def assert_dropped(self, source, frame, token, reason):
        # A full meter prevents policing from masking the validation result.
        time.sleep(METER_REFILL_SECONDS)
        observed = capture_token(self.lab, source, bytes(frame), token)
        count = sum(len(packets) for packets in observed.values())
        self.assertEqual(
            count,
            0,
            f"token {token!r}, {reason}: expected DROP, observed {count} "
            f"outputs; {observations_text(observed)}",
        )

    def assert_packet_integrity(
        self,
        sent,
        received,
        token,
        expected_port,
        qos_class,
        color,
        expected_dscp,
    ):
        expected_ecn = sent[IP].tos & 0x03
        context = (
            f"token {token!r}, class {qos_class}, expected {color} DSCP "
            f"{expected_dscp}, expected ECN {expected_ecn}"
        )
        destination = HOSTS[f"h{expected_port}"]

        self.assertEqual(received.src, destination["gateway_mac"], context)
        self.assertEqual(received.dst, destination["mac"], context)
        self.assertTrue(received.haslayer(IP), f"{context}: output is not IPv4")
        for field in (
            "src",
            "dst",
            "id",
            "version",
            "ihl",
            "len",
            "proto",
            "flags",
            "frag",
            "options",
        ):
            self.assertEqual(
                getattr(received[IP], field),
                getattr(sent[IP], field),
                f"{context}: IPv4 {field} changed",
            )
        self.assertEqual(
            received[IP].tos >> 2,
            expected_dscp,
            f"{context}: observed DSCP {received[IP].tos >> 2}",
        )
        self.assertEqual(
            received[IP].tos & 0x03,
            expected_ecn,
            f"{context}: observed ECN {received[IP].tos & 0x03}",
        )
        self.assertEqual(
            received[IP].ttl,
            sent[IP].ttl - 1,
            f"{context}: TTL was not decremented exactly once",
        )
        ip_header = bytes(received[IP])[: received[IP].ihl * 4]
        self.assertEqual(
            checksum(ip_header),
            0,
            f"{context}: forwarded IPv4 checksum is invalid",
        )

        if sent.haslayer(TCP):
            self.assertTrue(received.haslayer(TCP), f"{context}: TCP header is absent")
            for field in (
                "sport",
                "dport",
                "seq",
                "ack",
                "dataofs",
                "reserved",
                "flags",
                "window",
                "chksum",
                "urgptr",
                "options",
            ):
                self.assertEqual(
                    getattr(received[TCP], field),
                    getattr(sent[TCP], field),
                    f"{context}: TCP {field} changed",
                )
            self.assertEqual(
                bytes(received[TCP].payload),
                bytes(sent[TCP].payload),
                f"{context}: TCP payload changed",
            )
            self.assertEqual(
                transport_checksum(received[IP]),
                0,
                f"{context}: TCP checksum is invalid",
            )
        elif sent.haslayer(UDP):
            self.assertTrue(received.haslayer(UDP), f"{context}: UDP header is absent")
            for field in ("sport", "dport", "len", "chksum"):
                self.assertEqual(
                    getattr(received[UDP], field),
                    getattr(sent[UDP], field),
                    f"{context}: UDP {field} changed",
                )
            self.assertEqual(
                bytes(received[UDP].payload),
                bytes(sent[UDP].payload),
                f"{context}: UDP payload changed",
            )
            if sent[UDP].chksum != 0:
                self.assertEqual(
                    transport_checksum(received[IP]),
                    0,
                    f"{context}: UDP checksum is invalid",
                )

    def build_meter_frames(self, qos_class, label, sequence_base, count):
        source = None
        sent = {}
        frames = []
        for offset in range(count):
            token = f"qos-meter-{label}-{offset:02d}".encode()
            packet_source, packet = meter_packet(
                qos_class,
                token,
                sequence_base + offset,
            )
            if source is None:
                source = packet_source
            self.assertEqual(packet_source, source)
            sent[token] = packet
            frames.append(bytes(packet))
        return source, sent, frames

    def assert_meter_accounting(
        self,
        qos_class,
        sent,
        observed,
        green_dscp,
        yellow_dscp,
    ):
        by_token = data_observations_by_token(observed, sent)
        colors = {"GREEN": set(), "YELLOW": set(), "RED": set()}
        for token, sent_packet in sent.items():
            outputs = [
                (port, packet)
                for port, packets in by_token[token].items()
                for packet in packets
            ]
            if not outputs:
                colors["RED"].add(token)
                continue
            self.assertEqual(
                len(outputs),
                1,
                f"token {token!r}, class {qos_class}: observed {len(outputs)} "
                f"outputs; {observations_text(by_token[token])}",
            )
            port, frame = outputs[0]
            self.assertEqual(
                port,
                3,
                f"token {token!r}, class {qos_class}: observed egress {port}, want 3",
            )
            received = Ether(frame)
            self.assertTrue(
                received.haslayer(IP),
                f"token {token!r}, class {qos_class}: output is not IPv4",
            )
            observed_dscp = received[IP].tos >> 2
            if observed_dscp == green_dscp:
                color = "GREEN"
            elif observed_dscp == yellow_dscp:
                color = "YELLOW"
            else:
                self.fail(
                    f"token {token!r}, class {qos_class}: observed DSCP "
                    f"{observed_dscp}, want GREEN {green_dscp} or "
                    f"YELLOW {yellow_dscp}"
                )
            colors[color].add(token)
            self.assert_packet_integrity(
                sent_packet,
                received,
                token,
                3,
                qos_class,
                color,
                observed_dscp,
            )

        accounted = set().union(*colors.values())
        self.assertEqual(
            accounted,
            set(sent),
            f"class {qos_class}: sent and accounted token sets differ",
        )
        self.assertEqual(
            sum(len(tokens) for tokens in colors.values()),
            len(sent),
            f"class {qos_class}: color counts do not equal sent count",
        )
        return colors

    def run_meter_burst(self, qos_class, label, sequence_base):
        source, sent, frames = self.build_meter_frames(
            qos_class,
            label,
            sequence_base,
            METER_BURST_PACKETS,
        )
        observed = capture_batches(
            self.lab,
            ((source, frames),),
            sent,
        )
        if qos_class == "HIGH":
            green_dscp, yellow_dscp = 46, 10
        else:
            green_dscp, yellow_dscp = 0, 8
        return self.assert_meter_accounting(
            qos_class,
            sent,
            observed,
            green_dscp,
            yellow_dscp,
        )

    def test_topology_configuration(self):
        port_map = {
            port: self.lab.switch.intfs[port].name
            for port in self.lab.switch.intfs
            if port != 0
        }
        self.assertEqual(port_map, {1: "s1-eth1", 2: "s1-eth2", 3: "s1-eth3"})

        for name, config in HOSTS.items():
            host = self.lab.net.get(name)
            interface = f"{name}-eth0"
            self.assertEqual(host.IP(), config["ip"].split("/", 1)[0])
            self.assertEqual(host.MAC(), config["mac"])

            route, stderr, returncode = host.pexec("ip", "route", "show", "default")
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(
                route.strip(),
                f"default via {config['gateway_ip']} dev {interface}",
            )

            neighbor, stderr, returncode = host.pexec(
                "ip", "neigh", "show", config["gateway_ip"], "dev", interface
            )
            self.assertEqual(returncode, 0, stderr)
            self.assertEqual(
                neighbor.strip(),
                f"{config['gateway_ip']} lladdr {config['gateway_mac']} PERMANENT",
            )

    def test_high_tcp_preserves_every_ecn_value(self):
        for ecn in range(4):
            with self.subTest(ecn=ecn):
                token = f"qos-high-ecn-{ecn}".encode()
                packet = (
                    Ether(
                        src=HOSTS["h1"]["mac"],
                        dst=HOSTS["h1"]["gateway_mac"],
                    )
                    / IP(
                        src="10.0.1.1",
                        dst="10.0.3.1",
                        ttl=64,
                        id=0x1100 + ecn,
                        tos=(17 << 2) | ecn,
                    )
                    / TCP(
                        sport=12001 + ecn,
                        dport=443,
                        seq=0x10203040 + ecn,
                        ack=0x50607080 + ecn,
                        flags="PA",
                        window=4096,
                    )
                    / Raw(token)
                )
                self.assert_forwarded(
                    "h1",
                    packet,
                    token,
                    3,
                    "HIGH",
                    46,
                )

    def test_normal_udp_to_h3(self):
        token = b"qos-normal-udp-5000"
        packet = (
            Ether(src=HOSTS["h2"]["mac"], dst=HOSTS["h2"]["gateway_mac"])
            / IP(
                src="10.0.2.1",
                dst="10.0.3.1",
                ttl=61,
                id=0x2202,
                tos=(37 << 2) | 1,
            )
            / UDP(sport=22002, dport=5000)
            / Raw(token)
        )
        self.assert_forwarded("h2", packet, token, 3, "NORMAL", 0)

    def test_scavenger_udp_to_h3(self):
        token = b"qos-scavenger-udp-5001"
        packet = (
            Ether(src=HOSTS["h2"]["mac"], dst=HOSTS["h2"]["gateway_mac"])
            / IP(
                src="10.0.2.1",
                dst="10.0.3.1",
                ttl=59,
                id=0x2303,
                tos=(61 << 2) | 2,
            )
            / UDP(sport=23003, dport=5001)
            / Raw(token)
        )
        self.assert_forwarded("h2", packet, token, 3, "SCAVENGER", 8)

    def test_classifier_near_misses_default_to_normal(self):
        cases = (
            ("high-ingress", "h2", "10.0.1.200", "10.0.3.1", TCP, 443, 3),
            ("high-source", "h1", "10.0.2.200", "10.0.3.1", TCP, 443, 3),
            ("high-destination", "h1", "10.0.1.1", "10.0.2.1", TCP, 443, 2),
            ("high-protocol", "h1", "10.0.1.1", "10.0.3.1", UDP, 443, 3),
            ("high-port", "h1", "10.0.1.1", "10.0.3.1", TCP, 444, 3),
            ("scavenger-ingress", "h1", "10.0.2.200", "10.0.3.1", UDP, 5001, 3),
            ("scavenger-source", "h2", "10.0.1.200", "10.0.3.1", UDP, 5001, 3),
            ("scavenger-destination", "h2", "10.0.2.1", "10.0.1.1", UDP, 5001, 1),
            ("scavenger-protocol", "h2", "10.0.2.1", "10.0.3.1", TCP, 5001, 3),
        )
        for index, (
            name,
            source,
            ip_source,
            ip_destination,
            layer,
            port,
            egress,
        ) in enumerate(cases):
            with self.subTest(name=name):
                token = f"qos-near-miss-{index}".encode()
                transport = layer(sport=30000 + index, dport=port)
                if layer is TCP:
                    transport.seq = 0x60000000 + index
                    transport.ack = 0x70000000 + index
                    transport.flags = "PA"
                packet = (
                    Ether(
                        src=HOSTS[source]["mac"],
                        dst=HOSTS[source]["gateway_mac"],
                    )
                    / IP(
                        src=ip_source,
                        dst=ip_destination,
                        ttl=48 + index,
                        id=0x4000 + index,
                        tos=(([5, 17, 37, 61][index % 4]) << 2) | (index % 4),
                    )
                    / transport
                    / Raw(token)
                )
                self.assert_forwarded(
                    source,
                    packet,
                    token,
                    egress,
                    "NORMAL (classifier miss)",
                    0,
                )

    def test_bad_ipv4_checksum_drops(self):
        token = b"qos-bad-ipv4-checksum-001"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.0.3.200", ttl=64, id=0x5101)
            / UDP(sport=51001, dport=5001)
            / Raw(token)
        )
        frame = bytearray(bytes(serialized(packet)))
        header = slice(
            ETHERNET_HEADER_LENGTH,
            ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH,
        )
        self.assertEqual(checksum(bytes(frame[header])), 0)
        frame[ETHERNET_HEADER_LENGTH + 10] ^= 0x01
        self.assertNotEqual(checksum(bytes(frame[header])), 0)
        self.assert_dropped("h1", frame, token, "bad IPv4 checksum")

    def test_ipv4_fragments_drop(self):
        cases = (
            ("MF first fragment", "MF", 0, b"qos-ipv4-mf-fragment-001"),
            ("non-first fragment", 0, 3, b"qos-ipv4-offset-fragment-003"),
        )
        for reason, flags, offset, token in cases:
            with self.subTest(reason=reason):
                packet = (
                    Ether(
                        src=HOSTS["h1"]["mac"],
                        dst=HOSTS["h1"]["gateway_mac"],
                    )
                    / IP(
                        src="10.0.1.1",
                        dst="10.0.3.200",
                        ttl=64,
                        id=0x5102 + offset,
                        flags=flags,
                        frag=offset,
                    )
                    / UDP(sport=51002 + offset, dport=5001)
                    / Raw(token)
                )
                frame = bytes(serialized(packet))
                flags_offset = struct.unpack_from(
                    "!H",
                    frame,
                    ETHERNET_HEADER_LENGTH + 6,
                )[0]
                self.assertEqual(bool(flags_offset & 0x2000), flags == "MF")
                self.assertEqual(flags_offset & 0x1FFF, offset)
                self.assert_dropped("h1", frame, token, reason)

    def test_ipv4_options_drop(self):
        token = b"qos-ipv4-options-001"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(
                src="10.0.1.1",
                dst="10.0.3.200",
                ttl=64,
                id=0x5103,
                options=[IPOption(b"\x00\x00\x00\x00")],
            )
            / ICMP(type=8, id=0x5103)
            / Raw(token)
        )
        frame = bytes(packet)
        header_length = (frame[ETHERNET_HEADER_LENGTH] & 0x0F) * 4
        self.assertEqual(header_length, 24)
        self.assertEqual(
            checksum(
                frame[ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + header_length]
            ),
            0,
        )
        self.assertEqual(
            checksum(
                frame[
                    ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH
                ]
            ),
            0,
        )
        self.assert_dropped("h1", frame, token, "IPv4 options")

    def test_ipv4_version_mismatch_drops(self):
        token = b"qos-ipv4-version-6-drop"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.0.3.200", ttl=64, id=0x5106)
            / UDP(sport=51006, dport=5001)
            / Raw(token)
        )
        frame = bytearray(bytes(serialized(packet)))
        frame[ETHERNET_HEADER_LENGTH] = (6 << 4) | (
            frame[ETHERNET_HEADER_LENGTH] & 0x0F
        )
        checksum_offset = ETHERNET_HEADER_LENGTH + 10
        struct.pack_into("!H", frame, checksum_offset, 0)
        header = bytes(
            frame[ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH]
        )
        struct.pack_into("!H", frame, checksum_offset, checksum(header))
        self.assertEqual(frame[ETHERNET_HEADER_LENGTH] >> 4, 6)
        self.assertEqual(
            checksum(
                bytes(
                    frame[
                        ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH
                        + IPV4_HEADER_LENGTH
                    ]
                )
            ),
            0,
        )
        self.assert_dropped("h1", frame, token, "IPv4 version mismatch")

    def test_malformed_ipv4_lengths_drop(self):
        too_small_token = b"qos-ipv4-length-too-small-001"
        too_small_packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.0.3.200", ttl=64, id=0x5104)
            / UDP(sport=51004, dport=5001)
            / Raw(too_small_token)
        )
        too_small = with_ipv4_total_length(
            bytes(serialized(too_small_packet)),
            IPV4_HEADER_LENGTH - 1,
        )
        self.assertEqual(
            struct.unpack_from("!H", too_small, ETHERNET_HEADER_LENGTH + 2)[0],
            IPV4_HEADER_LENGTH - 1,
        )
        self.assertEqual(
            checksum(
                too_small[
                    ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH
                ]
            ),
            0,
        )
        self.assert_dropped(
            "h1",
            too_small,
            too_small_token,
            "IPv4 total length below the base header",
        )

        too_large_token = b"qos-ipv4-length-too-large-001"
        too_large_packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.0.3.200", ttl=64, id=0x5105)
            / ICMP(type=8, id=0x5105)
            / Raw(too_large_token)
        )
        frame = bytes(too_large_packet)
        claimed_length = len(frame) - ETHERNET_HEADER_LENGTH + 64
        too_large = with_ipv4_total_length(frame, claimed_length)
        self.assertLess(
            len(too_large),
            ETHERNET_HEADER_LENGTH + claimed_length,
        )
        self.assertEqual(
            checksum(
                too_large[
                    ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH
                ]
            ),
            0,
        )
        self.assert_dropped(
            "h1",
            too_large,
            too_large_token,
            "IPv4 total length exceeds the received frame",
        )

    def test_ttl_exhaustion_drops(self):
        for ttl in (1, 0):
            token = f"qos-ipv4-ttl-{ttl}-drop".encode()
            with self.subTest(ttl=ttl):
                packet = (
                    Ether(
                        src=HOSTS["h1"]["mac"],
                        dst=HOSTS["h1"]["gateway_mac"],
                    )
                    / IP(
                        src="10.0.1.1",
                        dst="10.0.3.200",
                        ttl=ttl,
                        id=0x5110 + ttl,
                    )
                    / UDP(sport=51100 + ttl, dport=5001)
                    / Raw(token)
                )
                frame = bytes(serialized(packet))
                self.assertEqual(frame[ETHERNET_HEADER_LENGTH + 8], ttl)
                self.assertEqual(
                    checksum(
                        frame[
                            ETHERNET_HEADER_LENGTH : ETHERNET_HEADER_LENGTH
                            + IPV4_HEADER_LENGTH
                        ]
                    ),
                    0,
                )
                self.assert_dropped(
                    "h1",
                    frame,
                    token,
                    f"IPv4 TTL {ttl}",
                )

    def test_meter_color_accounting_is_stable(self):
        expected_counts = {"GREEN": 2, "YELLOW": 2, "RED": 4}
        for run in range(3):
            with self.subTest(qos_class="HIGH", run=run):
                time.sleep(METER_REFILL_SECONDS)
                colors = self.run_meter_burst(
                    "HIGH",
                    f"high-stability-{run}",
                    100 + run * METER_BURST_PACKETS,
                )
                self.assertEqual(
                    {color: len(tokens) for color, tokens in colors.items()},
                    expected_counts,
                    f"HIGH run {run} color distribution changed",
                )

        time.sleep(METER_REFILL_SECONDS)
        colors = self.run_meter_burst("NORMAL", "normal-colors", 200)
        self.assertEqual(
            {color: len(tokens) for color, tokens in colors.items()},
            expected_counts,
            "NORMAL color distribution changed",
        )

    def test_meter_independent_class_state(self):
        time.sleep(METER_REFILL_SECONDS)
        high_source, high_sent, high_frames = self.build_meter_frames(
            "HIGH",
            "independent-high",
            300,
            METER_BURST_PACKETS,
        )
        normal_token = b"qos-meter-independent-normal"
        normal_source, normal_packet = meter_packet("NORMAL", normal_token, 320)
        observed = capture_batches(
            self.lab,
            (
                (high_source, high_frames),
                (normal_source, (bytes(normal_packet),)),
            ),
            (*high_sent, normal_token),
        )
        high_colors = self.assert_meter_accounting(
            "HIGH",
            high_sent,
            observed,
            46,
            10,
        )
        self.assertTrue(high_colors["RED"], "HIGH burst did not exhaust its meter")
        normal_colors = self.assert_meter_accounting(
            "NORMAL",
            {normal_token: normal_packet},
            observed,
            0,
            8,
        )
        self.assertEqual(
            normal_colors["GREEN"],
            {normal_token},
            f"NORMAL did not remain GREEN after HIGH exhaustion: {normal_colors}",
        )

        time.sleep(METER_REFILL_SECONDS)
        normal_source, normal_sent, normal_frames = self.build_meter_frames(
            "NORMAL",
            "independent-normal-burst",
            330,
            METER_BURST_PACKETS,
        )
        high_token = b"qos-meter-independent-high"
        high_source, high_packet = meter_packet("HIGH", high_token, 350)
        observed = capture_batches(
            self.lab,
            (
                (normal_source, normal_frames),
                (high_source, (bytes(high_packet),)),
            ),
            (*normal_sent, high_token),
        )
        normal_colors = self.assert_meter_accounting(
            "NORMAL",
            normal_sent,
            observed,
            0,
            8,
        )
        self.assertTrue(normal_colors["RED"], "NORMAL burst did not exhaust its meter")
        high_colors = self.assert_meter_accounting(
            "HIGH",
            {high_token: high_packet},
            observed,
            46,
            10,
        )
        self.assertEqual(
            high_colors["GREEN"],
            {high_token},
            f"HIGH did not remain GREEN after NORMAL exhaustion: {high_colors}",
        )

    def test_meter_refill_restores_green(self):
        time.sleep(METER_REFILL_SECONDS)
        colors = self.run_meter_burst("HIGH", "refill-burst", 400)
        self.assertTrue(colors["YELLOW"], "refill burst produced no YELLOW packets")
        self.assertTrue(colors["RED"], "refill burst produced no RED packets")

        time.sleep(METER_REFILL_SECONDS)
        token = b"qos-meter-refill-green"
        _, packet = meter_packet("HIGH", token, 420)
        self.assert_forwarded("h1", packet, token, 3, "HIGH", 46)

    def test_reverse_h3_to_h1(self):
        token = b"qos-forward-rev-003"
        packet = (
            Ether(src=HOSTS["h3"]["mac"], dst=HOSTS["h3"]["gateway_mac"])
            / IP(src="10.0.3.1", dst="10.0.1.1", ttl=47, id=0x3303)
            / UDP(sport=33003, dport=7000)
            / Raw(token)
        )
        self.assert_forwarded("h3", packet, token, 1, "NORMAL (classifier miss)", 0)

    def test_reverse_h3_to_h2(self):
        token = b"qos-forward-rev-005"
        packet = (
            Ether(src=HOSTS["h3"]["mac"], dst=HOSTS["h3"]["gateway_mac"])
            / IP(src="10.0.3.1", dst="10.0.2.1", ttl=51, id=0x3505)
            / UDP(sport=35005, dport=7100)
            / Raw(token)
        )
        self.assert_forwarded("h3", packet, token, 2, "NORMAL (classifier miss)", 0)

    def test_route_miss_drops(self):
        token = b"qos-route-miss-004"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.99.0.1", ttl=64, id=0x4404)
            / UDP(sport=44004, dport=9000)
            / Raw(token)
        )
        self.assert_dropped(
            "h1",
            bytes(serialized(packet)),
            token,
            "IPv4 route miss",
        )
        self.lab.program(CONTROLLER, P4INFO, DEVICE_CONFIG, verify_only=True)


@unittest.skipUnless(os.geteuid() == 0, "Mininet integration tests require root")
class LifecycleIntegrationTest(unittest.TestCase):
    def test_normal_cleanup(self):
        lab = QosNetwork()
        with lab:
            lab.program(CONTROLLER, P4INFO, DEVICE_CONFIG)
            node_pids = [node.pid for node in lab.net.hosts + lab.net.switches]
        assert_lab_clean(self, lab, node_pids)

    def test_controller_failure_cleanup(self):
        lab = QosNetwork()
        with tempfile.TemporaryDirectory(prefix="p4-qos-invalid-") as directory:
            invalid_config = Path(directory) / "invalid.json"
            invalid_config.write_bytes(b"not a BMv2 pipeline")
            with self.assertRaisesRegex(RuntimeError, "controller exited"):
                with lab:
                    node_pids = [node.pid for node in lab.net.hosts + lab.net.switches]
                    lab.program(CONTROLLER, P4INFO, invalid_config)
        assert_lab_clean(self, lab, node_pids)


if __name__ == "__main__":
    unittest.main()
