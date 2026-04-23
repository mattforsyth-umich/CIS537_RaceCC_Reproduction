#!/usr/bin/env python3

import socket
import subprocess
import sys
import time
import threading
from scapy.all import (
    IP, Ether, Packet, IntField, Raw,
    get_if_hwaddr, get_if_list,
    sendp, sniff, bind_layers
)

# Total bits per packet including all headers
PACKET_SIZE_BITS = (1400 + 20 + 4 + 14) * 8

class RaceCC(Packet):
    name = "RaceCC"
    fields_desc = [
        IntField("rate", 1000000)
    ]

bind_layers(IP, RaceCC, proto=0xFD)

def get_interface():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    exit(1)

def get_my_ip(iface):
    result = subprocess.run(['ip', 'addr', 'show', iface],
                            capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line:
            return line.strip().split()[1].split('/')[0]
    return None

# Start at the max rate (about 55 pkt/s)
current_rate = int(PACKET_SIZE_BITS / 1000 * 55)

def handle_feedback(pkt, my_ip):
    global current_rate

    if not (IP in pkt and pkt[IP].proto == 0xFD and RaceCC in pkt):
        return
    if pkt[IP].dst != my_ip:
        return

    new_rate = pkt[RaceCC].rate

    if new_rate != current_rate:
        print(f"Rate updated: {current_rate} -> {new_rate} Kbps")
        sys.stdout.flush()

    current_rate = new_rate

def main():
    global current_rate

    if len(sys.argv) < 2:
        print('pass 1 argument: <destination>')
        exit(1)

    dest_addr  = socket.gethostbyname(sys.argv[1])
    iface      = get_interface()
    my_ip      = get_my_ip(iface)

    print(f"Sending on interface {iface} to {dest_addr}")
    print(f"My IP is {my_ip}")

    # Listen for rate update ACKs in the background
    sniffer_thread = threading.Thread(
        target=lambda: sniff(
            iface=iface,
            prn=lambda x: handle_feedback(x, my_ip),
            store=False
        ),
        daemon=True
    )
    sniffer_thread.start()

    start_time = time.time()
    end_time   = start_time + 90
    pkt_count  = 0

    while time.time() < end_time:
        pkt = (Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
               / IP(dst=dest_addr, proto=0xFD)
               / RaceCC(rate=current_rate)
               / Raw(b'X' * 1400))

        send_start = time.time()
        sendp(pkt, iface=iface, verbose=False)
        pkt_count += 1

        # Sleep just long enough between packets to match the target rate.
        # the time sendp() took to run is subtracted
        rate_bps   = current_rate * 1000
        gap        = PACKET_SIZE_BITS / rate_bps
        elapsed    = time.time() - send_start
        sleep_time = gap - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

        if pkt_count % 100 == 0:
            elapsed = time.time() - start_time
            print(f"Sent {pkt_count} packets in {elapsed:.1f}s, current rate={current_rate} Kbps")
            sys.stdout.flush()

    print(f"Done. Sent {pkt_count} packets total.")

if __name__ == '__main__':
    main()
