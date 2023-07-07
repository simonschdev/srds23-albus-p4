/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */

#define GAMMA 64w54
#define BETA  64w270
#define TIMEOUT 64w5
#define RANDOM_THRESHOLD 32w1000
#define PUSH_THRESHOLD 64w1000

#define N_CELLS 32

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    // Leaky bucket data
    register<bit<32>>(N_CELLS) LB_flow_ids;
    register<bit<64>>(N_CELLS) LB_counts;
    register<bit<64>>(N_CELLS) LB_timestamps;

    register<bit<64>>(4) debug_reg;

    // Prefiltering counter data
    register<bit<32>>(N_CELLS) PC_flow_ids;
    register<bit<64>>(N_CELLS) PC_counts;

    // -----------------------------------------------------------------------------
    // ALBUS algorithm

    action block() {
        meta.blacklist_report.srcAddr = hdr.ipv4.srcAddr;
        meta.blacklist_report.dstAddr = hdr.ipv4.dstAddr;
        meta.blacklist_report.srcPort = hdr.tcp.srcPort;
        meta.blacklist_report.dstPort = hdr.tcp.dstPort;
        meta.blacklist_report.protocol = hdr.ipv4.protocol;
        digest<blacklist_report_t>(1, meta.blacklist_report);
        mark_to_drop(standard_metadata);
    }

    table check_block {
        key = {
            standard_metadata.mcast_grp: exact;
        }
        actions = {
            block;
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }

    action albus_update(bit<9> egress_port){

        standard_metadata.egress_spec = egress_port;

        // Get flow ID and cell index
        bit<32> flow_id;
        hash(flow_id, HashAlgorithm.crc32_custom, (bit<16>)0, \
             {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, \
             (bit<32>)4294967295);
        //bit<64> flow_id = (bit<64>)meta.flow_id;
        if (flow_id == 32w0) {
            flow_id = 32w1;
        }
        bit<32> cell_index_long;
        hash(cell_index_long, HashAlgorithm.crc32_custom, (bit<16>)0, \
             {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, \
             (bit<32>)N_CELLS);
        bit<5> cell_index = cell_index_long[4:0];
        meta.cell_index = (bit<32>) cell_index;

        // Cell variables
        bit<32> LB_flow_id;
        bit<64> LB_timestamp;
        bit<64> LB_count;
        bit<32> PC_flow_id;
        bit<64> PC_count;

        bit<32> random_val;
        bit<32> random_val_difference;

        // Read values from cell
        LB_flow_ids.read(LB_flow_id, meta.cell_index);
        LB_timestamps.read(LB_timestamp, meta.cell_index);
        LB_counts.read(LB_count, meta.cell_index);

        PC_flow_ids.read(PC_flow_id, meta.cell_index);
        PC_counts.read(PC_count, meta.cell_index);

        // Intermediate variables for processing 
        bit<64> LB_drain;
        bit<64> LB_excess_burstiness;

        bit<64> packet_size = (bit<64>) standard_metadata.packet_length;

        bit<64> branch_taken = 64w0;

        bit<64> LB_count_new = LB_count;
        bit<64> PC_count_new = PC_count;

        bool too_bursty = false;
        bool evict = false;
        bool zero_timestamp = false;
        bool push_threshold_exceeded = false;
        bool randomness_hit = false;

        random(random_val, (bit<32>)0, (bit<32>)100000);

        bit<64> now = (bit<64>)(standard_metadata.ingress_global_timestamp);
        bit<64> passed_time = (now - LB_timestamp) >> 18;

        if (LB_flow_id == flow_id) {

            LB_drain = GAMMA * passed_time;
            LB_count = LB_count |-| LB_drain;
            LB_count = LB_count + packet_size;
            LB_excess_burstiness = packet_size |-| LB_drain;

            zero_timestamp = (LB_timestamp == 64w0);
            too_bursty = (LB_count > BETA);
            evict = (LB_excess_burstiness == 64w0);

            if (zero_timestamp) {

                branch_taken = 1;

                // Flow was pulled from PC before - now we really start monitoring it
                LB_timestamp = now;
                LB_count_new = packet_size + 64w0;

            } else if (too_bursty) {

                branch_taken = 2;

                // Found bursty flow! -> send to controller
                standard_metadata.mcast_grp = 16w65535;

                LB_flow_id = PC_flow_id;
                LB_timestamp = 64w0;
                LB_count_new = 64w0; 

            } else if (evict) {

                branch_taken = 3;

                // Eviction for lack of burstiness
                LB_flow_id = PC_flow_id;
                LB_count_new = 64w0;
                LB_timestamp = 64w0;

                PC_flow_id = 32w0;
                PC_count_new = 64w0;

            } else {

                branch_taken = 4;

                LB_timestamp = now;
                LB_count_new = LB_count + 64w0;

            }

        } else if (LB_flow_id == 32w0) {

            branch_taken = 5;

            // Assign unassigned LB
            LB_flow_id = flow_id;
            LB_count_new = packet_size;
            LB_timestamp = now;

        } else if (passed_time > TIMEOUT) {

            branch_taken = 6;

            // Eviction b/c of timeout
            LB_flow_id = PC_flow_id;
            LB_count_new = 64w0;
            LB_timestamp = 64w0;

        } else if (PC_flow_id == flow_id) {

            branch_taken = 7;

            // Flow is assigned to PC
            PC_count_new = PC_count + packet_size;

            push_threshold_exceeded = (PC_count > PUSH_THRESHOLD);

            if (push_threshold_exceeded) {
                LB_flow_id = PC_flow_id;
                LB_timestamp = now;
                LB_count_new = packet_size;
                PC_flow_id = 32w0;
                PC_count_new = 64w0;
                branch_taken = 7777;
            }

        } else if (PC_flow_id == 32w0) {

            branch_taken = 8;

            // PC is unassigned
            PC_flow_id = flow_id;
            PC_count_new = packet_size;

        } else {

            random_val_difference = RANDOM_THRESHOLD |-| random_val;
            randomness_hit = (random_val_difference != 32w0);
            if (randomness_hit) {

                branch_taken = 9;

                // Update PC
                PC_count_new = PC_count |-| packet_size;

            } else {

                branch_taken = 10;

            }

        }

        // Weird, but somehow ensures that counts are correctly updated
        LB_count = LB_count_new;
        PC_count = PC_count_new;

        // Update registers (has to be done outside the conditional structure)
        LB_flow_ids.write(meta.cell_index, LB_flow_id);
        LB_counts.write(meta.cell_index, LB_count);
        LB_timestamps.write(meta.cell_index, LB_timestamp);

        PC_flow_ids.write(meta.cell_index, PC_flow_id);
        PC_counts.write(meta.cell_index, PC_count);

        // For debugging
        debug_reg.write(0, LB_drain);
        debug_reg.write(1, LB_excess_burstiness);
        debug_reg.write(2, branch_taken);

    }

    // Necessary for path discovery at the beginning
    action forward_reply(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // -----------------------------------------------------------------------------
    // Processing packet
    table process_packet {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            albus_update;
            forward_reply;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    // -----------------------------------------------------------------------------
    // Called when the blacklist matches
    action drop() {
        meta.blacklisted = 1;
        mark_to_drop(standard_metadata);
    }

    // -----------------------------------------------------------------------------
    // This (initially applied) table will be filled with
    //  blacklist rules for flows identified as malicious: drop
    table blacklist {
        key = {
            hdr.ipv4.srcAddr:  exact;
            hdr.ipv4.dstAddr:  exact;
            hdr.tcp.srcPort:   exact;
            hdr.tcp.dstPort:   exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    // Entry point for ingress processing logic
    apply {

        // Check lookup table for flow:
        //  - if flow is marked as blacklisted: drop,
        //  - if no action was applied, the flag meta.blacklisted will be 0 
        blacklist.apply();

        // Sketching
        if (meta.blacklisted == 0) {

            process_packet.apply();
            check_block.apply();

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;