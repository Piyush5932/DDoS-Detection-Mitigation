#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from packet_logger import PacketLogger
import time
import random
from datetime import datetime

def generate_test_packets(num_packets=10):
    """Generate test packet data for logging"""
    logger = PacketLogger()
    print(f"Packet logger initialized. Log file: {logger.log_file}")
    
    # Generate some normal packets
    for i in range(num_packets):
        # Create random packet data
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(80, 8080)
        protocol = random.choice([6, 17])  # TCP or UDP
        
        pkt_data = {
            'src_mac': f"00:1A:2B:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'dst_mac': f"00:3C:4D:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_size': random.randint(64, 1500),
            'flags': 'ACK:1,SYN:0,FIN:0,RST:0' if protocol == 6 else 'N/A'
        }
        
        # Log as normal packet
        logger.log_packet(pkt_data, status='normal')
        print(f"Logged normal packet {i+1}/{num_packets}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        time.sleep(0.1)
    
    # Generate some blocked packets
    for i in range(num_packets // 2):
        # Create random packet data for attack
        src_ip = f"192.168.2.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(80, 8080)
        
        pkt_data = {
            'src_mac': f"00:5E:6F:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'dst_mac': f"00:7G:8H:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': 6,  # TCP
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_size': random.randint(64, 1500),
            'flags': 'ACK:0,SYN:1,FIN:0,RST:0'
        }
        
        # Log as blocked packet
        reason = random.choice(["Flood attack detected", "ML model detection", "Blacklisted source"])
        logger.log_packet(pkt_data, status='blocked', reason=reason)
        print(f"Logged blocked packet {i+1}/{num_packets//2}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (Reason: {reason})")
        time.sleep(0.1)
    
    print(f"\nLogging complete. Total packets logged: {num_packets + (num_packets // 2)}")
    print(f"Log file location: {logger.log_file}")
    return logger.log_file

if __name__ == "__main__":
    log_file = generate_test_packets(20)
    print("\nTo view the logs, run:")
    print(f"python view_logs.py --file \"{log_file}\"")