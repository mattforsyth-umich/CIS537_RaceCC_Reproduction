#!/usr/bin/env python3

import os
import sys
import csv
import time
import subprocess
from scapy.all import (
    IP, Ether, Packet, IntField, ByteField,
    get_if_hwaddr, get_if_list,
    sniff, sendp, bind_layers
)

# If more than 30% of packets in a window came back CE marked, tell the sender
CE_CONGESTION_THRESHOLD = 0.3

class ECNFeedback(Packet):
    name = "ECNFeedback"
    fields_desc = [
        IntField("rate", 1000000),
        ByteField("congested", 0)
    ]

bind_layers(IP, ECNFeedback, proto=0xFE)

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

# Per-flow counters, values reset each second
packets_in_window  = {}
ce_marked_in_window = {}
window_start_time  = {}
last_seen_rate     = {}

log_path = '/home/p4/CIS537_RaceCC_Reproduction/exercises/Host_Driven_ECN/ecn_convergence.csv'
log_file = open(log_path, 'w', newline='')
writer   = csv.writer(log_file)
writer.writerow(['elapsed_s', 'src_ip', 'rate_kbps', 'pps', 'ce_fraction', 'congested'])
log_file.flush()

print(f"Logging to {log_path}")
print(f"{'Time':>10}  {'Flow':>12}  {'Rate':>10}  {'PPS':>6}  {'CE_frac':>8}  {'Cong':>5}")
print('-' * 60)
sys.stdout.flush()

def handle_pkt(pkt, my_ip, iface):
    global packets_in_window, ce_marked_in_window, window_start_time, last_seen_rate

    if not (IP in pkt and pkt[IP].proto == 0xFE and ECNFeedback in pkt):
        return

    sender_ip = pkt[IP].src
    dest_ip   = pkt[IP].dst

    if dest_ip != my_ip or sender_ip == my_ip:
        return

    sender_rate = pkt[ECNFeedback].rate
    now         = time.time()

    # Check if the switch marked this packet as congestion experienced
    ecn_bits = pkt[IP].tos & 0x3
    is_ce    = (ecn_bits == 3)

    # First packet from this sender, set up tracking for it
    if sender_ip not in packets_in_window:
        packets_in_window[sender_ip]   = 0
        ce_marked_in_window[sender_ip] = 0
        window_start_time[sender_ip]   = now
        last_seen_rate[sender_ip]      = sender_rate
        print(f"[{now - experiment_start:8.3f}s] New flow: {sender_ip}")
        sys.stdout.flush()

    packets_in_window[sender_ip] += 1
    if is_ce:
        ce_marked_in_window[sender_ip] += 1

    window_duration = now - window_start_time[sender_ip]

    if window_duration >= 1.0:
        total_pkts  = packets_in_window[sender_ip]
        ce_pkts     = ce_marked_in_window[sender_ip]
        pps         = total_pkts / window_duration
        elapsed     = now - experiment_start
        ce_fraction = ce_pkts / total_pkts if total_pkts > 0 else 0.0
        congested   = 1 if ce_fraction >= CE_CONGESTION_THRESHOLD else 0

        writer.writerow([f'{elapsed:.3f}', sender_ip, sender_rate,
                         f'{pps:.1f}', f'{ce_fraction:.4f}', congested])
        log_file.flush()

        print(f"{elapsed:>9.3f}s  {sender_ip:>12}  {sender_rate:>7} Kbps  "
              f"{pps:>5.1f} pps  {ce_fraction:>7.4f}  {congested:>5}")
        sys.stdout.flush()

        # Reset counters for next window
        packets_in_window[sender_ip]   = 0
        ce_marked_in_window[sender_ip] = 0
        window_start_time[sender_ip]   = now
        last_seen_rate[sender_ip]      = sender_rate

        # Send ACK back so the sender knows whether to cut its rate
        ack = (Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
               / IP(src=my_ip, dst=sender_ip, proto=0xFE)
               / ECNFeedback(rate=sender_rate, congested=congested))
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
