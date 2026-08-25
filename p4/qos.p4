#define V1MODEL_VERSION 20200408

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> IP_PROTOCOL_TCP = 6;
const bit<8> IP_PROTOCOL_UDP = 17;

const bit<8> CLASS_HIGH = 1;
const bit<8> CLASS_NORMAL = 2;
const bit<8> CLASS_SCAVENGER = 3;

const bit<2> METER_GREEN = 0;
const bit<2> METER_YELLOW = 1;
const bit<2> METER_RED = 2;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> reserved;
    bit<1> ns;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata_t {
    bit<16> l4SrcPort;
    bit<16> l4DstPort;
    bit<8> qosClass;
    bit<2> meterColor;
}

parser MyParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    meter<bit<8>>(4, MeterType.packets) class_meter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_qos_class(bit<8> class_id) {
        meta.qosClass = class_id;
    }

    action ipv4_forward(
        PortId_t egress_port,
        bit<48> src_mac,
        bit<48> dst_mac)
    {
        standard_metadata.egress_spec = egress_port;
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table qos_classifier {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.ipv4.protocol: ternary;
            meta.l4SrcPort: ternary;
            meta.l4DstPort: ternary;
        }
        actions = {
            set_qos_class;
        }
        size = 64;
        default_action = set_qos_class(CLASS_NORMAL);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 32;
        const default_action = drop();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            standard_metadata.checksum_error != 0 ||
            !hdr.ethernet.isValid() ||
            !hdr.ipv4.isValid()) {
            drop();
            exit;
        }

        if (hdr.ipv4.version != 4 ||
            hdr.ipv4.ihl != 5 ||
            hdr.ipv4.totalLen < 20 ||
            standard_metadata.packet_length <
                32w14 + (bit<32>) hdr.ipv4.totalLen ||
            hdr.ipv4.ttl <= 1 ||
            hdr.ipv4.flags[0:0] == 1 ||
            hdr.ipv4.fragOffset != 0) {
            drop();
            exit;
        }

        if (hdr.tcp.isValid()) {
            if (hdr.ipv4.totalLen < 40 ||
                hdr.tcp.dataOffset < 5 ||
                (bit<32>) hdr.ipv4.totalLen <
                    32w20 + (bit<32>) hdr.tcp.dataOffset * 32w4) {
                drop();
                exit;
            }
            meta.l4SrcPort = hdr.tcp.srcPort;
            meta.l4DstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            if (hdr.udp.length < 8 ||
                (bit<32>) hdr.ipv4.totalLen !=
                    32w20 + (bit<32>) hdr.udp.length) {
                drop();
                exit;
            }
            meta.l4SrcPort = hdr.udp.srcPort;
            meta.l4DstPort = hdr.udp.dstPort;
        } else {
            meta.l4SrcPort = 0;
            meta.l4DstPort = 0;
        }

        qos_classifier.apply();
        if (meta.qosClass < CLASS_HIGH || meta.qosClass > CLASS_SCAVENGER) {
            drop();
            exit;
        }

        class_meter.execute_meter(meta.qosClass, meta.meterColor);
        if (meta.meterColor == METER_GREEN) {
            if (meta.qosClass == CLASS_HIGH) {
                hdr.ipv4.dscp = 46;
            } else if (meta.qosClass == CLASS_NORMAL) {
                hdr.ipv4.dscp = 0;
            } else {
                hdr.ipv4.dscp = 8;
            }
        } else if (meta.meterColor == METER_YELLOW) {
            if (meta.qosClass == CLASS_HIGH) {
                hdr.ipv4.dscp = 10;
            } else {
                hdr.ipv4.dscp = 8;
            }
        } else if (meta.meterColor == METER_RED) {
            drop();
            exit;
        } else {
            drop();
            exit;
        }

        ipv4_lpm.apply();
    }
}

control MyEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply { }
}

control MyComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()) main;
