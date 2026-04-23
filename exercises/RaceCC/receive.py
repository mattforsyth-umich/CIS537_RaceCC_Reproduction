#!/usr/bin/env python3

import os
import sys
import csv
import time
import subprocess
from scapy.all import (
    IP, Ether, Packet, IntField,
    get_if_hwaddr, get_if_list,
    sniff, sendp, bind_layers
)

class RaceCC(Packet):
    name = "RaceCC"
    fields_desc = [ IntField("rate", 1000000) ]

bind_layers(IP, RaceCC, proto=0xFD)

def get_interface():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0")
    exit(1)

def get_my_ip(iface):
    result = subprocess.run(['ip', 'addr', 'show', iface],
                            capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line:
            return line.strip().split()[1].split('/')[0]
    return None

experiment_start = time.time()

# Per-flow counters
packets_in_window = {}
window_start_time = {}
last_seen_rate    = {}

log_path = '/home/p4/CIS537_RaceCC_Reproduction/exercises/RaceCC/convergence.csv'
log_file = open(log_path, 'w', newline='')
writer   = csv.writer(log_file)
writer.writerow(['elapsed_s', 'src_ip', 'rate_kbps', 'pps'])
log_file.flush()

print(f"Logging to {log_path}")
print(f"{'Time':>10}  {'Flow':>12}  {'Rate':>10}  {'PPS':>6}")
print('-' * 46)
sys.stdout.flush()

def handle_pkt(pkt, my_ip, iface):
    global packets_in_window, window_start_time, last_seen_rate

    if not (IP in pkt and pkt[IP].proto == 0xFD and RaceCC in pkt):
        return

    sender_ip = pkt[IP].src
    dest_ip   = pkt[IP].dst

    if dest_ip != my_ip or sender_ip == my_ip:
        return

    sender_rate = pkt[RaceCC].rate
    now         = time.time()

    # Start tracking the sender when a new flow starts
    if sender_ip not in packets_in_window:
        packets_in_window[sender_ip] = 0
        window_start_time[sender_ip] = now
        last_seen_rate[sender_ip]    = sender_rate
        print(f"[{now - experiment_start:8.3f}s] New flow: {sender_ip}")
        sys.stdout.flush()

    packets_in_window[sender_ip] += 1

    window_duration = now - window_start_time[sender_ip]

    if window_duration >= 1.0:
        pps     = packets_in_window[sender_ip] / window_duration
        elapsed = now - experiment_start

        writer.writerow([f'{elapsed:.3f}', sender_ip, sender_rate, f'{pps:.1f}'])
        log_file.flush()

        print(f"{elapsed:>9.3f}s  {sender_ip:>12}  {sender_rate:>7} Kbps  {pps:>5.1f} pps")
        sys.stdout.flush()

        # Reset counters for the next window
        packets_in_window[sender_ip] = 0
        window_start_time[sender_ip] = now
        last_seen_rate[sender_ip]    = sender_rate

    # Send the rate back to the sender in an ACK packet
    ack = (Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
           / IP(src=my_ip, dst=sender_ip, proto=0xFD)
           / RaceCC(rate=sender_rate))
    sendp(ack, iface=iface, verbose=False)

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface  = ifaces[0]
    my_ip  = get_my_ip(iface)

    print(f"Sniffing on {iface}, my IP is {my_ip}")
    sys.stdout.flush()

    try:
        sniff(iface=iface, prn=lambda x: handle_pkt(x, my_ip, iface))
    except KeyboardInterrupt:
        pass
    finally:
        log_file.close()
        print(f"\nSaved to {log_path}")

if __name__ == '__main__':
    main()
