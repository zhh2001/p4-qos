import argparse
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import Link
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Switch


DEVICE_ID = 1
DEFAULT_GRPC_ADDRESS = "127.0.0.1:50051"
DEFAULT_THRIFT_PORT = 9090

HOSTS = {
    "h1": {
        "ip": "10.0.1.1/24",
        "mac": "02:00:00:00:01:01",
        "gateway_ip": "10.0.1.254",
        "gateway_mac": "02:00:00:00:01:fe",
        "port": 1,
    },
    "h2": {
        "ip": "10.0.2.1/24",
        "mac": "02:00:00:00:02:01",
        "gateway_ip": "10.0.2.254",
        "gateway_mac": "02:00:00:00:02:fe",
        "port": 2,
    },
    "h3": {
        "ip": "10.0.3.1/24",
        "mac": "02:00:00:00:03:01",
        "gateway_ip": "10.0.3.254",
        "gateway_mac": "02:00:00:00:03:fe",
        "port": 3,
    },
}


class P4RuntimeSwitch(Switch):
    def __init__(
        self,
        name,
        switch_binary,
        grpc_address,
        thrift_port,
        runtime_path,
        **params,
    ):
        super().__init__(name, **params)
        self.switch_binary = switch_binary
        self.grpc_address = grpc_address
        self.thrift_port = thrift_port
        self.runtime_path = Path(runtime_path)
        self.process = None
        self._log = None

    def start(self, controllers):
        del controllers
        interfaces = {
            port: self.intfs[port].name for port in sorted(self.intfs) if port != 0
        }
        expected = {index: f"s1-eth{index}" for index in range(1, 4)}
        if interfaces != expected:
            raise RuntimeError(f"switch port map is {interfaces}, expected {expected}")

        command = [self.switch_binary]
        for port, interface in interfaces.items():
            command.extend(("-i", f"{port}@{interface}"))
        command.extend(
            (
                "--device-id",
                str(DEVICE_ID),
                "--thrift-port",
                str(self.thrift_port),
                "--notifications-addr",
                f"ipc://{self.runtime_path / 'notifications.ipc'}",
                "--log-level",
                "warn",
                "--no-p4",
                "--",
                "--grpc-server-addr",
                self.grpc_address,
            )
        )

        self._log = (self.runtime_path / "switch.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=self._log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def stop(self, deleteIntfs=True):
        process = self.process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        if self._log is not None:
            self._log.close()
            self._log = None
        super().stop(deleteIntfs=deleteIntfs)


class QosNetwork:
    def __init__(
        self,
        grpc_address=DEFAULT_GRPC_ADDRESS,
        thrift_port=DEFAULT_THRIFT_PORT,
        switch_binary="simple_switch_grpc",
    ):
        self.grpc_address = grpc_address
        self.thrift_port = thrift_port
        self.switch_binary = switch_binary
        self.net = None
        self.switch = None
        self.runtime_path = None
        self.switch_pid = None
        self._runtime = None

    def __enter__(self):
        if os.geteuid() != 0:
            raise PermissionError("Mininet requires root privileges")
        self._preflight()
        self._runtime = tempfile.TemporaryDirectory(prefix="p4-qos-")
        self.runtime_path = Path(self._runtime.name)
        try:
            self._start()
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup_error:
                error.add_note(f"cleanup also failed: {cleanup_error}")
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            exc_value.add_note(f"cleanup also failed: {cleanup_error}")
        return False

    def _preflight(self):
        binary = shutil.which(self.switch_binary)
        if binary is None:
            raise FileNotFoundError(f"switch binary {self.switch_binary!r} not found")
        self.switch_binary = binary

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
                continue
            raise RuntimeError(f"interface {interface} already exists")

        host, port = _split_address(self.grpc_address)
        _require_port_free(host, port)
        _require_port_free("0.0.0.0", self.thrift_port)

    def _start(self):
        self.net = Mininet(controller=None, build=False, link=Link)
        hosts = {
            name: self.net.addHost(name, ip=config["ip"], mac=config["mac"])
            for name, config in HOSTS.items()
        }
        self.switch = self.net.addSwitch(
            "s1",
            cls=P4RuntimeSwitch,
            switch_binary=self.switch_binary,
            grpc_address=self.grpc_address,
            thrift_port=self.thrift_port,
            runtime_path=self.runtime_path,
        )
        for name, config in HOSTS.items():
            self.net.addLink(
                hosts[name],
                self.switch,
                port1=0,
                port2=config["port"],
                intfName1=f"{name}-eth0",
                intfName2=f"s1-eth{config['port']}",
            )

        self.net.build()
        self._configure_interfaces(hosts)
        self.net.start()
        self.switch_pid = self.switch.process.pid

        host, grpc_port = _split_address(self.grpc_address)
        _wait_for_port(host, grpc_port, self.switch.process, self._switch_log)
        _wait_for_port(
            "127.0.0.1", self.thrift_port, self.switch.process, self._switch_log
        )

    def _configure_interfaces(self, hosts):
        expected = {index: f"s1-eth{index}" for index in range(1, 4)}
        actual = {
            port: self.switch.intfs[port].name
            for port in self.switch.intfs
            if port != 0
        }
        if actual != expected:
            raise RuntimeError(f"switch port map is {actual}, expected {expected}")

        for name, config in HOSTS.items():
            host = hosts[name]
            host_interface = f"{name}-eth0"
            switch_interface = f"s1-eth{config['port']}"
            self.switch.intfs[config["port"]].setMAC(config["gateway_mac"])

            _node_command(
                host,
                "sysctl",
                "-q",
                "-w",
                f"net.ipv6.conf.{host_interface}.disable_ipv6=1",
            )
            _node_command(
                self.switch,
                "sysctl",
                "-q",
                "-w",
                f"net.ipv6.conf.{switch_interface}.disable_ipv6=1",
            )
            _disable_offloads(host, host_interface)
            _disable_offloads(self.switch, switch_interface)
            _node_command(
                host,
                "ip",
                "neigh",
                "replace",
                config["gateway_ip"],
                "lladdr",
                config["gateway_mac"],
                "nud",
                "permanent",
                "dev",
                host_interface,
            )
            _node_command(
                host,
                "ip",
                "route",
                "replace",
                "default",
                "via",
                config["gateway_ip"],
                "dev",
                host_interface,
            )

    def _switch_log(self):
        if self.switch is None or self.switch._log is None:
            return ""
        self.switch._log.flush()
        path = self.runtime_path / "switch.log"
        return path.read_text(encoding="utf-8", errors="replace")

    def program(
        self,
        controller_path,
        p4info_path,
        device_config_path,
        verify_only=False,
    ):
        if self.net is None or self.switch.process.poll() is not None:
            raise RuntimeError("switch is not running")
        command = [
            str(Path(controller_path).resolve()),
            "--address",
            self.grpc_address,
            "--device-id",
            str(DEVICE_ID),
            "--p4info",
            str(Path(p4info_path).resolve()),
            "--device-config",
            str(Path(device_config_path).resolve()),
        ]
        if verify_only:
            command.append("--verify-only")
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(
                f"controller exited with status {completed.returncode}: {detail}"
            )
        return completed.stdout.strip()

    def close(self):
        net, self.net = self.net, None
        cleanup_error = None
        try:
            if net is not None:
                net.stop()
        except BaseException as error:
            cleanup_error = error

        if cleanup_error is not None and net is not None:
            for link in net.links:
                try:
                    link.stop()
                except BaseException:
                    pass
            for switch in net.switches:
                try:
                    switch.stop()
                except BaseException:
                    pass
                try:
                    switch.terminate()
                except BaseException:
                    pass
            for host in net.hosts:
                try:
                    host.terminate()
                except BaseException:
                    pass

        process = None if self.switch is None else self.switch.process
        if process is not None and process.poll() is None:
            try:
                self.switch.stop(deleteIntfs=False)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error

        if self._runtime is not None:
            try:
                self._runtime.cleanup()
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            self._runtime = None

        if cleanup_error is not None:
            raise cleanup_error


def _node_command(node, *command):
    stdout, stderr, returncode = node.pexec(*command)
    if returncode != 0:
        detail = stderr.strip() or stdout.strip()
        raise RuntimeError(
            f"{node.name}: {' '.join(command)} exited with status "
            f"{returncode}: {detail}"
        )


def _disable_offloads(node, interface):
    _node_command(
        node,
        "ethtool",
        "--offload",
        interface,
        "rx",
        "off",
        "tx",
        "off",
        "sg",
        "off",
        "tso",
        "off",
        "gso",
        "off",
        "gro",
        "off",
        "lro",
        "off",
    )


def _split_address(address):
    try:
        host, port_text = address.rsplit(":", 1)
        port = int(port_text)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"invalid address {address!r}") from error
    if not host or not 1 <= port <= 65535:
        raise ValueError(f"invalid address {address!r}")
    return host, port


def _require_port_free(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, port))


def _wait_for_port(host, port, process, log_reader, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"switch exited with status {process.returncode}: {log_reader().strip()}"
            )
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(
        f"switch did not listen on {host}:{port}: {log_reader().strip()}"
    )


def _parse_args():
    parser = argparse.ArgumentParser(description="Run the IPv4 QoS Mininet lab")
    parser.add_argument("--controller", default="build/qos-controller")
    parser.add_argument("--p4info", default="build/qos.p4info.txtpb")
    parser.add_argument("--device-config", default="build/qos.json")
    parser.add_argument("--address", default=DEFAULT_GRPC_ADDRESS)
    parser.add_argument("--thrift-port", type=int, default=DEFAULT_THRIFT_PORT)
    return parser.parse_args()


def main():
    args = _parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges")
    setLogLevel("info")

    previous = signal.getsignal(signal.SIGTERM)

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    try:
        with QosNetwork(args.address, args.thrift_port) as lab:
            print(lab.program(args.controller, args.p4info, args.device_config))
            print(
                lab.program(
                    args.controller,
                    args.p4info,
                    args.device_config,
                    verify_only=True,
                )
            )
            CLI(lab.net)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
