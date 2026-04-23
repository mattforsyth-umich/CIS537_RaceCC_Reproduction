#!/usr/bin/env python3

import socket
import subprocess
import sys
import time
import threading
from scapy.all import (
    IP, Ether, Packet, IntField, ByteField, Raw,
    get_if_hwaddr, get_if_list,
    sendp, sniff, bind_layers
)

PACKET_SIZE_BITS   = (1400 + 20 + 4 + 14) * 8
LINK_CAPACITY_KBPS = 575

# How fast alpha reacts to congestion signals. Higher value means
# the sender forgets old history faster and reacts more to recent packets
EWMA_WEIGHT = 0.35

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
    print("Cannot find eth0 interface")
    exit(1)

def get_my_ip(iface):
    result = subprocess.run(['ip', 'addr', 'show', iface],
                            capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line:
            return line.strip().split()[1].split('/')[0]
    return None

# Start at full link capacity and let congestion bring  the rate down
current_rate = int(LINK_CAPACITY_KBPS)

# estimate of how congested the path is, between 0.0 and 1.0
congestion_alpha = 0.0

rate_lock = threading.Lock()

def handle_feedback(pkt, my_ip):
    global current_rate, congestion_alpha

    if not (IP in pkt and pkt[IP].proto == 0xFE and ECNFeedback in pkt):
        return
    if pkt[IP].dst != my_ip:
        return

    congested = pkt[ECNFeedback].congested

    with rate_lock:
        # Update the congestion estimate using EWMA
        if congested:
            congestion_alpha = (1 - EWMA_WEIGHT) * congestion_alpha + EWMA_WEIGHT * 1.0
        else:
            congestion_alpha = congestion_alpha * (1 - EWMA_WEIGHT)

        old_rate = current_rate

        if congested:
            # Cut rate proportionally to how congested the path is
            # The floor prevents the rate from dropping to zero
            ratio    = current_rate / max(LINK_CAPACITY_KBPS, 1)
            cut      = congestion_alpha * min(0.5, max(0.05, ratio * 0.5))
            new_rate = int(current_rate * (1.0 - cut))
            floor    = int(LINK_CAPACITY_KBPS * (1.0 - congestion_alpha))
            new_rate = max(floor, new_rate)
        else:
            # Increase additively, but increase less aggressively if the rate is
            # close to link capacity
            ratio    = current_rate / max(LINK_CAPACITY_KBPS, 1)
            increase = (1.0 - congestion_alpha) * (1.0 - ratio)
            new_rate = int(current_rate + max(5, increase * LINK_CAPACITY_KBPS * 0.20))

        new_rate = max(1, min(LINK_CAPACITY_KBPS, new_rate))

        if new_rate != current_rate:
            print(f"[feedback] congested={congested} alpha={congestion_alpha:.4f} "
                  f"rate: {old_rate} -> {new_rate} Kbps")
            sys.stdout.flush()

        current_rate = new_rate

def main():
    global current_rate

    if len(sys.argv) < 2:
        print('pass 1 argument: <destination>')
        exit(1)

    dest_addr = socket.gethostbyname(sys.argv[1])
    iface     = get_interface()
    my_ip     = get_my_ip(iface)

    print(f"Sending on interface {iface} to {dest_addr}")
    print(f"My IP is {my_ip}")
    sys.stdout.flush()

    # Listen for ACKs from the receiver in the background
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
        with rate_lock:
            rate_snapshot = current_rate

        pkt = (Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
               / IP(dst=dest_addr, proto=0xFE, tos=0x01)
               / ECNFeedback(rate=rate_snapshot, congested=0)
               / Raw(b'X' * 1400))

        send_start = time.time()
        sendp(pkt, iface=iface, verbose=False)
        pkt_count += 1

        # Sleep just long enough to hit the target rate
        rate_bps   = rate_snapshot * 1000
        gap        = PACKET_SIZE_BITS / rate_bps
        elapsed    = time.time() - send_start
        sleep_time = gap - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

        if pkt_count % 100 == 0:
            elapsed = time.time() - start_time
            print(f"Sent {pkt_count} packets in {elapsed:.1f}s, "
                  f"rate={rate_snapshot} Kbps alpha={congestion_alpha:.4f}")
            sys.stdout.flush()

    print(f"Done. Sent {pkt_count} packets total.")

if __name__ == '__main__':
    main()
