// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHER_IPV4     = 0x800;
const bit<8>  PROTO_FEEDBACK = 0xFE;
const bit<19> QUEUE_LIMIT    = 5;

typedef bit<9>  port_t;
typedef bit<48> mac_t;
typedef bit<32> ipv4_t;

header ethernet_t {
    mac_t    dst;
    mac_t    src;
    bit<16>  etherType;
}

header ipv4_hdr_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   diffserv;
    bit<2>   ecn;
    bit<16>  totalLen;
    bit<16>  id;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  checksum;
    ipv4_t   src;
    ipv4_t   dstAddr;
}

// header for congestion and rate tracking
// Sender to Receiver: rate carries the sender's current tx rate
// Receiver to Sender: congested tells the sender it is an ACK packet
header feedback_t {
    bit<32> rate;
    bit<8>  congested;
}

struct metadata { }

struct headers {
    ethernet_t   ethernet;
    ipv4_hdr_t   ipv4;
    feedback_t   fb;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_IPV4: parse_ip;
            default:    accept;
        }
    }

    state parse_ip {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_FEEDBACK: parse_feedback;
            default:        accept;
        }
    }

    state parse_feedback {
        packet.extract(hdr.fb);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_t dstAddr, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src = hdr.ethernet.dst;
        hdr.ethernet.dst = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid() && hdr.fb.isValid()) {
            // Only update outgoing data packets, not returning ACKs
            // Receiver sets congested=1 on ACKs so we can tell them apart
            if (hdr.fb.congested == 0) {
                // If the sender marked this packet ECN-capable and the queue
                // is growing, flip the ECN bits to signal congestion
                if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2) {
                    if (standard_metadata.enq_qdepth >= QUEUE_LIMIT) {
                        hdr.ipv4.ecn = 3;
                    }
                }
            }
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.id,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src,
              hdr.ipv4.dstAddr },
            hdr.ipv4.checksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.fb);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
