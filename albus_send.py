#!/usr/bin/python3

# This script is adapted from
# the p4-learning utilities:
# https://github.com/nsg-ethz/p4-learning/blob/master/exercises/07-Count-Min-Sketch/solution/send.py

from packet_generator import *

import pickle
import sys
import time

BETA = 270

def save_flows(flows):
    with open("sent_flows.pickle", "wb") as f:
        pickle.dump(flows, f)

def main(n_heavy_hitters, n_small_flows, overuse_ratio, interval, trace_length):

    random.seed(1)

    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    intf_name = getInterfaceName()
    send_socket.bind((intf_name, 0))

    eth_h = eth_header("01:02:20:aa:33:aa", "02:02:20:aa:33:aa", 0x800)
    
    heavy_hitters = []
    while len(heavy_hitters) < n_heavy_hitters:
        random_flow = get_random_flow()
        if random_flow not in heavy_hitters:
            heavy_hitters.append(random_flow)

    print(heavy_hitters)

    small_flows = []
    while len(small_flows) < n_small_flows:
        random_flow = get_random_flow()
        if random_flow not in heavy_hitters+small_flows:
            small_flows.append(random_flow)

    flows = heavy_hitters + small_flows
    #save flows in a file so the controller can compare
    save_flows(flows)

    # ---- Create trace building blocks
    packet_queue_normal = []
    packet_queue_normal += flows
    random.shuffle(packet_queue_normal)
    time_step_normal = interval / len(packet_queue_normal)

    packet_queue_burst = []
    for heavy_hitter in heavy_hitters:
        packet_queue_burst += [heavy_hitter] * (int(BETA/54 * overuse_ratio) + 1)
    packet_queue_burst += small_flows
    random.shuffle(packet_queue_burst)
    time_step_burst = interval / len(packet_queue_burst)

    # --- Create trace
    packet_queue = []
    time_steps   = []
    interval_counter = -1
    timer = 0
    while timer < trace_length:

        curr_interval_counter = int(timer/interval)

        if curr_interval_counter != interval_counter:
            interval_counter = curr_interval_counter
            if interval_counter % 4 == 3:
                packet_queue += packet_queue_burst
                time_steps   += [timer+i*time_step_burst for i in range(len(packet_queue_burst))]
            else:
                packet_queue += packet_queue_normal
                time_steps   += [timer+i*time_step_normal for i in range(len(packet_queue_normal))]
            timer = (interval_counter + 1) * interval 


    # --- Send traffic according to trace
    queue_counter = 0
    first_time = time.time()
    while queue_counter < len(packet_queue):

        while time.time() - first_time < time_steps[queue_counter]:
            time.sleep(0.00001)

        flow = packet_queue[queue_counter]
        packet = create_packet_ip_tcp(eth_h, *flow)
        send_socket.send(packet)

        queue_counter += 1

    send_socket.close()


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('--n-hh',  type=int,   required=False, default=10)   # Number of heavy hitters
    parser.add_argument('--n-sf',  type=int,   required=False, default=990)  # Number of small flows
    parser.add_argument('--our',   type=float, required=False, default=1.0)  # Overuse ratio
    parser.add_argument('--intv',  type=float, required=False, default=0.25) # Interval between packets
    parser.add_argument('--len',   type=float, required=False, default=1.0)  # Trace length
    args = parser.parse_args()

    main(args.n_hh, args.n_sf, int(args.our), args.intv, args.len)


