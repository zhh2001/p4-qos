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

from scapy.all import ICMP, Ether, IP, Raw, TCP, UDP


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
CAPTURE_SECONDS = 0.35

SEND_FRAME = """
import socket
import sys

frame = bytes.fromhex(sys.argv[2])
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
    sender.bind((sys.argv[1], 0))
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


def send_from(host, interface, frame):
    sender = host.popen(
        [sys.executable, "-c", SEND_FRAME, interface, frame.hex()],
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


def capture_token(lab, source, frame, token):
    captures = open_captures()
    observed = {port: [] for port in captures}
    try:
        send_from(lab.net.get(source), f"{source}-eth0", frame)
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
                    if address[2] != PACKET_OUTGOING or token not in packet:
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

    def assert_forwarded(self, source, packet, token, expected_port):
        sent = serialized(packet)
        observed = capture_token(self.lab, source, bytes(sent), token)
        data = data_observations(observed)
        count = sum(len(packets) for packets in data.values())
        self.assertEqual(
            count,
            1,
            f"token {token!r} produced {count} egress packets; "
            f"{observations_text(observed)}",
        )
        self.assertEqual(
            len(data[expected_port]),
            1,
            f"token {token!r} did not use port {expected_port}; "
            f"{observations_text(observed)}",
        )
        received = Ether(data[expected_port][0])
        destination = HOSTS[f"h{expected_port}"]

        self.assertEqual(received.src, destination["gateway_mac"])
        self.assertEqual(received.dst, destination["mac"])
        self.assertEqual(received[IP].src, sent[IP].src)
        self.assertEqual(received[IP].dst, sent[IP].dst)
        self.assertEqual(received[IP].id, sent[IP].id)
        self.assertEqual(received[IP].version, sent[IP].version)
        self.assertEqual(received[IP].ihl, sent[IP].ihl)
        self.assertEqual(received[IP].len, sent[IP].len)
        self.assertEqual(received[IP].proto, sent[IP].proto)
        self.assertEqual(received[IP].ttl, sent[IP].ttl - 1)
        ip_header = bytes(received[IP])[: received[IP].ihl * 4]
        self.assertEqual(checksum(ip_header), 0, "forwarded IPv4 checksum is invalid")
        return sent, received

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

    def test_tcp_h1_to_h3(self):
        token = b"qos-forward-tcp-001"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.0.3.1", ttl=64, id=0x1101)
            / TCP(
                sport=12001,
                dport=443,
                seq=0x10203040,
                ack=0x50607080,
                flags="PA",
                window=4096,
            )
            / Raw(token)
        )
        sent, received = self.assert_forwarded("h1", packet, token, 3)

        self.assertEqual(received[TCP].sport, sent[TCP].sport)
        self.assertEqual(received[TCP].dport, sent[TCP].dport)
        self.assertEqual(received[TCP].seq, sent[TCP].seq)
        self.assertEqual(received[TCP].ack, sent[TCP].ack)
        self.assertEqual(int(received[TCP].flags), int(sent[TCP].flags))
        self.assertEqual(bytes(received[Raw].load), token)
        self.assertEqual(received[TCP].chksum, sent[TCP].chksum)
        self.assertEqual(transport_checksum(received[IP]), 0, "TCP checksum is invalid")

    def test_udp_h2_to_h3(self):
        token = b"qos-forward-udp-002"
        packet = (
            Ether(src=HOSTS["h2"]["mac"], dst=HOSTS["h2"]["gateway_mac"])
            / IP(src="10.0.2.1", dst="10.0.3.1", ttl=61, id=0x2202)
            / UDP(sport=22002, dport=5000)
            / Raw(token)
        )
        sent, received = self.assert_forwarded("h2", packet, token, 3)

        self.assertEqual(received[UDP].sport, sent[UDP].sport)
        self.assertEqual(received[UDP].dport, sent[UDP].dport)
        self.assertEqual(received[UDP].len, sent[UDP].len)
        self.assertEqual(bytes(received[Raw].load), token)
        self.assertNotEqual(sent[UDP].chksum, 0)
        self.assertEqual(received[UDP].chksum, sent[UDP].chksum)
        self.assertEqual(transport_checksum(received[IP]), 0, "UDP checksum is invalid")

    def test_reverse_h3_to_h1(self):
        token = b"qos-forward-rev-003"
        packet = (
            Ether(src=HOSTS["h3"]["mac"], dst=HOSTS["h3"]["gateway_mac"])
            / IP(src="10.0.3.1", dst="10.0.1.1", ttl=47, id=0x3303)
            / UDP(sport=33003, dport=7000)
            / Raw(token)
        )
        sent, received = self.assert_forwarded("h3", packet, token, 1)
        self.assertEqual(received[UDP].sport, sent[UDP].sport)
        self.assertEqual(received[UDP].dport, sent[UDP].dport)
        self.assertEqual(received[UDP].len, sent[UDP].len)
        self.assertEqual(bytes(received[Raw].load), token)
        self.assertNotEqual(sent[UDP].chksum, 0)
        self.assertEqual(received[UDP].chksum, sent[UDP].chksum)
        self.assertEqual(transport_checksum(received[IP]), 0, "UDP checksum is invalid")

    def test_reverse_h3_to_h2(self):
        token = b"qos-forward-rev-005"
        packet = (
            Ether(src=HOSTS["h3"]["mac"], dst=HOSTS["h3"]["gateway_mac"])
            / IP(src="10.0.3.1", dst="10.0.2.1", ttl=51, id=0x3505)
            / UDP(sport=35005, dport=7100)
            / Raw(token)
        )
        sent, received = self.assert_forwarded("h3", packet, token, 2)
        self.assertEqual(received[UDP].sport, sent[UDP].sport)
        self.assertEqual(received[UDP].dport, sent[UDP].dport)
        self.assertEqual(received[UDP].len, sent[UDP].len)
        self.assertEqual(bytes(received[Raw].load), token)
        self.assertNotEqual(sent[UDP].chksum, 0)
        self.assertEqual(received[UDP].chksum, sent[UDP].chksum)
        self.assertEqual(transport_checksum(received[IP]), 0, "UDP checksum is invalid")

    def test_route_miss_drops(self):
        token = b"qos-route-miss-004"
        packet = (
            Ether(src=HOSTS["h1"]["mac"], dst=HOSTS["h1"]["gateway_mac"])
            / IP(src="10.0.1.1", dst="10.99.0.1", ttl=64, id=0x4404)
            / UDP(sport=44004, dport=9000)
            / Raw(token)
        )
        sent = bytes(serialized(packet))
        observed = capture_token(self.lab, "h1", sent, token)
        data = data_observations(observed)
        count = sum(len(packets) for packets in data.values())
        self.assertEqual(
            count,
            0,
            f"route-miss token {token!r} was forwarded; {observations_text(observed)}",
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
