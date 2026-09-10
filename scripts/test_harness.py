#!/usr/bin/env python3
"""
Firewall Attack Vector Test Harness
Simulates network attack vectors to validate eBPF detection & automatic blocking.
"""

import sys
import time
import argparse
from scapy.all import send, IP, TCP, UDP, ICMP

def print_status(msg, color="33"):
    print(f"\033[{color}m[*]\033[0m {msg}")

def syn_flood(target_ip, target_port, count):
    print_status(f"Starting TCP SYN Flood -> {target_ip}:{target_port} ({count} packets)", "31")
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(pkt, count=count, verbose=False)

def udp_flood(target_ip, target_port, count):
    print_status(f"Starting UDP Flood -> {target_ip}:{target_port} ({count} packets)", "31")
    pkt = IP(dst=target_ip) / UDP(dport=target_port) / ("X" * 1024)
    send(pkt, count=count, verbose=False)

def icmp_ping_flood(target_ip, count):
    print_status(f"Starting ICMP Ping Flood -> {target_ip} ({count} packets)", "31")
    pkt = IP(dst=target_ip) / ICMP() / ("PING" * 64)
    send(pkt, count=count, verbose=False)

def port_scan(target_ip, start_port, end_port):
    print_status(f"Starting Port Scan -> {target_ip} (Ports {start_port}-{end_port})", "31")
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="eBPF Firewall Test Harness")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("-c", "--count", type=int, default=1500, help="Number of packets per attack burst")
    args = parser.parse_args()

    print_status(f"Targeting {args.target}. Ensure TUI firewall is running on target interface!", "32")
    time.sleep(2)

    try:
        # Test 1: TCP SYN Flood
        syn_flood(args.target, 80, args.count)
        time.sleep(3)

        # Test 2: UDP High-Volume Flood
        udp_flood(args.target, 53, args.count)
        time.sleep(3)

        # Test 3: ICMP Echo Flood
        icmp_ping_flood(args.target, args.count)
        time.sleep(3)

        # Test 4: Port Scan Burst
        port_scan(args.target, 20, 120)

        print_status("Attack simulation suite completed successfully!", "32")

    except KeyboardInterrupt:
        print_status("\nTest harness aborted by user.", "31")
        sys.exit(0)

if __name__ == "__main__":
    main()
