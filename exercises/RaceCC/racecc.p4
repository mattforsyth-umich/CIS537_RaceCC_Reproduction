// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4   = 0x800;
const bit<8>  TYPE_RACECC = 0xFD;

// Mininet link is max 575 kbps
const bit<32> LINK_CAPACITY_KBPS = 575;
// target 546 kbps before backing off
const bit<32> ETA_B_KBPS = 546;
const bit<32> ADDITIVE_DECREASE_STEP = 3;
// Anything above this triggers MD instead of AD
const bit<32> MD_THRESHOLD_BYTES = 5;

// update the fair rate once per 100ms
const bit<48> UPDATE_INTERVAL_US   = 100000;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// The RaceCC header carries a single rate field that the switch overwrites with fair rate
header racecc_t {
    bit<32> rate;
}

struct metadata { }

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    racecc_t   racecc;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_RACECC: parse_racecc;
            default:     accept;
        }
    }

    state parse_racecc {
        packet.extract(hdr.racecc);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
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

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // One register entry per egress port (up to 8 ports)
    register<bit<32>>(8) fair_rate;
    register<bit<32>>(8) tx_bytes;
    register<bit<32>>(8) tx_bytes_last;
    register<bit<48>>(8) last_update;
    register<bit<32>>(8) inc_flag;

    apply {
        bit<32> egress_port_idx = (bit<32>)standard_metadata.egress_port;


        // Keeps track of Tx bytes for the current port
        bit<32> total_tx_bytes;
        tx_bytes.read(total_tx_bytes, egress_port_idx);
        total_tx_bytes = total_tx_bytes + standard_metadata.packet_length;
        tx_bytes.write(egress_port_idx, total_tx_bytes);

        // fair rate is computed using a similar algorithm to RaceCC
        // Rate is only calculated for packets with h5 as the destination address
        if (hdr.racecc.isValid() && hdr.ipv4.dstAddr == 0x0A000505) {

            bit<32> fair_rate_kbps;
            bit<32> tx_bytes_at_last_update;
            bit<48> last_update_time;
            
            // used to ensure rate is only increase max every other update
            bit<32> can_increase;

            fair_rate.read(fair_rate_kbps, egress_port_idx);
            tx_bytes_last.read(tx_bytes_at_last_update, egress_port_idx);
            last_update.read(last_update_time, egress_port_idx);
            inc_flag.read(can_increase, egress_port_idx);

            // if fair rate hasnt already been determined, start at half the max rate
            if (fair_rate_kbps == 0) {
                fair_rate_kbps = LINK_CAPACITY_KBPS >> 1;
                fair_rate.write(egress_port_idx, fair_rate_kbps);
            }

            bit<32> queue_depth = (bit<32>)standard_metadata.enq_qdepth;

            bit<48> current_time = standard_metadata.ingress_global_timestamp;
            bit<48> time_since_update = current_time - last_update_time;
            bit<32> bytes_since_last_update = total_tx_bytes - tx_bytes_at_last_update;

            // rough approximation of kbps based on tx bytes since last fair rate update
            bit<32> tx_rate_kbps = bytes_since_last_update >> 4;

            //if at least 100ms have passed since last calculation, recalc fair rate
            if (time_since_update >= UPDATE_INTERVAL_US) {

                bit<32> updated_rate        = fair_rate_kbps;
                bit<32> updated_can_increase = can_increase;

                if (queue_depth > MD_THRESHOLD_BYTES) {
                    // If the queue is building past the threshold, cut rate by ~6.25%
                    updated_rate = fair_rate_kbps - (fair_rate_kbps >> 4);
                    updated_can_increase = 1;

                } else if (queue_depth > 0) {
                    // Small queue but not over threshold results in fixed, small rate subtraction
                    if (fair_rate_kbps > ADDITIVE_DECREASE_STEP) {
                        updated_rate = fair_rate_kbps - ADDITIVE_DECREASE_STEP;
                    } else {
                        // if rate is smaller than the step, set to 1 to avoid a negative #
                        updated_rate = 1;
                    }
                    updated_can_increase = 1;

                } else if (bytes_since_last_update > 0 && tx_rate_kbps < ETA_B_KBPS) {
                    // No queue and link isnt at full utilization
                    // Increase is determined by current actual rate and current fair rate
                    if (can_increase == 1) {
                        if (tx_rate_kbps < 109) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps << 2); // fi=-2: x5
                        } else if (tx_rate_kbps < 184) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps << 1); // fi=-1: x3
                        } else if (tx_rate_kbps < 270) {
                            updated_rate = fair_rate_kbps + fair_rate_kbps;         // fi=0: x2
                        } else if (tx_rate_kbps < 363) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps >> 1); // fi=1: x1.5
                        } else if (tx_rate_kbps < 437) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps >> 2); // fi=2: x1.25
                        } else if (tx_rate_kbps < 485) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps >> 3); // fi=3: x1.125
                        } else if (tx_rate_kbps < 516) {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps >> 4); // fi=4: x1.0625
                        } else {
                            updated_rate = fair_rate_kbps + (fair_rate_kbps >> 5); // fi=5: x1.03125
                        }
                        updated_can_increase = 0;
                    } else {
                        // rate did not change
                        updated_rate        = fair_rate_kbps;
                        updated_can_increase = 1;
                    }

                } else {
                    // Link is at or above target utilization, no queue — hold steady
                    updated_rate        = fair_rate_kbps;
                    updated_can_increase = 1;
                }

                // Don't let the rate go out of bounds in either direction
                if (updated_rate > LINK_CAPACITY_KBPS) {
                    updated_rate = LINK_CAPACITY_KBPS;
                }
                if (updated_rate < 1) {
                    updated_rate = 1;
                }

                fair_rate.write(egress_port_idx, updated_rate);
                inc_flag.write(egress_port_idx, updated_can_increase);
                tx_bytes_last.write(egress_port_idx, total_tx_bytes);
                last_update.write(egress_port_idx, current_time);

                fair_rate_kbps = updated_rate;
            }

            // Write the current fair rate into the packet so the receiver
            // can echo it back to the sender in the ACK
            if (fair_rate_kbps != 0) {
                hdr.racecc.rate = fair_rate_kbps;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.racecc);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
