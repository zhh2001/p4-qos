# IPv4 QoS with P4Runtime

This project is a basic IPv4 QoS reference implementation for P4_16, v1model, BMv2 `simple_switch_grpc`, P4Runtime, and Mininet. The P4 data plane classifies traffic, applies a class-indexed packet meter, marks DSCP by meter color, drops RED excess packets, and performs normal IPv4 forwarding.

## Topology

```text
                 h3 receiver
                 10.0.3.1/24
                       |
                    3  |
                     [s1]
                    /    \
                 1 /      \ 2
                  /        \
       h1 premium          h2 best effort
       10.0.1.1/24         10.0.2.1/24
```

Switch ports, addresses, and MAC addresses are fixed:

| Host | Switch port | Host MAC | Gateway MAC |
| --- | ---: | --- | --- |
| `h1` | 1 | `02:00:00:00:01:01` | `02:00:00:00:01:fe` |
| `h2` | 2 | `02:00:00:00:02:01` | `02:00:00:00:02:fe` |
| `h3` | 3 | `02:00:00:00:03:01` | `02:00:00:00:03:fe` |

Each host has a static default route through its synthetic gateway and a permanent neighbor entry. The switch installs `/24` routes for all three host networks and rewrites both Ethernet addresses. ARP is not handled in P4.

## Classification and marking

`qos_classifier` is a P4Runtime-configurable ternary table. The controller installs these rules:

| Priority | Match | Class | Class ID |
| ---: | --- | --- | ---: |
| 30 | port 1, `10.0.1.0/24` to `10.0.3.0/24`, TCP destination 443 | HIGH | 1 |
| 30 | port 2, `10.0.2.0/24` to `10.0.3.0/24`, UDP destination 5000 | NORMAL | 2 |
| 10 | port 2, `10.0.2.0/24` to `10.0.3.0/24`, other UDP traffic | SCAVENGER | 3 |

A classifier miss selects NORMAL. Classification uses packet fields and table entries; it is not hardcoded as imperative policy in the P4 ingress control.

The color policy is:

| Class | GREEN DSCP | YELLOW DSCP | RED |
| --- | ---: | ---: | --- |
| HIGH | 46 | 10 | drop |
| NORMAL | 0 | 8 | drop |
| SCAVENGER | 8 | 8 | drop |

GREEN packets are forwarded with the preferred class marking. YELLOW packets
are remarked and forwarded. RED packets are dropped.

The IPv4 header declares DSCP and ECN as separate 6-bit and 2-bit fields. Changing DSCP therefore preserves the ECN bits exactly. Tests cover Not-ECT, ECT(1), ECT(0), and CE inputs. Queue-depth congestion marking is not part of this baseline; the data plane never changes ECN.

## Metering and policing

`class_meter` is an indirect v1model packet meter. Meter indexes 1, 2, and 3 belong to HIGH, NORMAL, and SCAVENGER respectively, so token state is class-based rather than per-flow and is independent between classes. Index 0 is unused.

All three meter entries are configured through P4Runtime with these test-friendly parameters:

| Parameter | Value |
| --- | ---: |
| Committed information rate | 5 packets/s |
| Committed burst | 2 packets |
| Peak information rate | 10 packets/s |
| Peak burst | 4 packets |

The full-bucket refill calculation is `max(2 / 5, 4 / 10) = 0.4 seconds`; tests add a 0.1-second scheduling margin. An eight-packet burst is checked token by token and produces the expected BMv2 policy result of two GREEN, two YELLOW, and four RED packets. Repeated bursts, refill back to GREEN on the same switch, and meter independence in both directions are automated tests.

This is policing, not shaping. The meter classifies packets by rate, after which the policy forwards, remarks, or drops them. It never delays excess packets for later release.

## IPv4 behavior

Forwarded packets have TTL decremented exactly once and receive a recomputed IPv4 header checksum after DSCP and TTL changes. The switch rejects incoming IPv4 checksum failures, TTL values of zero or one, versions other than 4, IHL values other than 5, total lengths below the base header or beyond the received frame, and route misses.

IPv4 options and fragmentation are unsupported. Packets with MF set or a nonzero fragment offset are dropped. IPv4 source and destination addresses, TCP/UDP fields, transport checksums, and payload are otherwise unchanged. A zero UDP checksum remains zero.

## P4Runtime controller

The Go controller uses [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller) for arbitration, pipeline installation, table programming, and meter access. It becomes primary for device ID 1, installs the pipeline, three routes, three classifier entries, the NORMAL default action, and three meter configurations. It then reads back and compares the P4Info, BMv2 device configuration, route entries, classifier entries and default, and every meter entry.

`--verify-only` performs the same readback without writing. `make run` invokes both programming and verification before opening the Mininet CLI.

## Prerequisites

- Linux with root privileges for Mininet and raw packet sockets
- `p4c-bm2-ss` with P4_16 and v1model support
- BMv2 `simple_switch_grpc`
- Mininet
- Go 1.25 or newer
- Python 3 with Scapy
- `iproute2` and `ethtool`

P4Runtime TCP port 50051 and BMv2 Thrift port 9090 must be free. The build does not install or modify the system toolchain.

## Build, run, and test

```sh
make build
```

This writes the P4Info, BMv2 JSON, and controller binary under the ignored `build/` directory.

```sh
make run
```

The command starts BMv2, programs and verifies it through P4Runtime, and opens an interactive Mininet prompt. Exiting the prompt tears down the owned switch, hosts, interfaces, processes, and temporary runtime directory.

```sh
make test
```

The complete suite builds the P4 and Go programs, runs Go tests and `go vet`, checks generated P4Info and BMv2 structure, compiles the Python sources, and runs packet-level Mininet tests. Unique payload tokens verify classification, DSCP and ECN, GREEN/YELLOW/RED accounting, no duplication, forwarding fields, checksums, refill, independent meter state, invalid-packet drops, and cleanup. The integration portion uses `sudo` through the configured `SUDO` make variable.

```sh
make clean
```

This removes only project build outputs and local Python cache files.

## Limitations

This is a basic QoS reference implementation, not a complete DiffServ policy engine. The markings are a small demonstration policy and do not claim a complete RFC-defined per-hop behavior.

There is no traffic shaping, queue scheduler, priority-queue baseline, queue-depth ECN marking, WFQ, DRR, HTB, hierarchical QoS, per-flow meter or queue state, IPv4 fragmentation, IPv4 options, IPv6, or ARP processing. Priority queue behavior is intentionally outside the implemented and tested baseline.
