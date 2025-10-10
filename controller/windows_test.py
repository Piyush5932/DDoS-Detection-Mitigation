import socket
import time
import random
import threading
import os
import sys

def send_packet(target_ip, target_port, protocol, is_attack=False, source_ip=None):
    """Send a packet to the target using raw sockets"""
    if source_ip is None:
        source_ip = f"10.0.0.{random.randint(1, 254)}"
    
    try:
        if protocol == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            try:
                s.connect_ex((target_ip, target_port))
                if is_attack:
                    s.send(b"A" * 1024)  # Send larger payload for attack
                else:
                    s.send(b"Normal traffic")
            except:
                pass
            finally:
                s.close()
        elif protocol == "UDP":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if is_attack:
                s.sendto(b"A" * 1024, (target_ip, target_port))
            else:
                s.sendto(b"Normal traffic", (target_ip, target_port))
            s.close()
        
        # Print packet info in a format similar to what the controller would see
        attack_str = "ATTACK" if is_attack else "NORMAL"
        print(f"PACKET: {source_ip} -> {target_ip} [{protocol}] {attack_str}")
        
        return True
    except Exception as e:
        print(f"Error sending {protocol} packet: {e}")
        return False

def simulate_normal_traffic(target_ip, target_port, num_packets=10):
    """Simulate normal traffic to the controller"""
    print(f"Sending {num_packets} normal packets to {target_ip}:{target_port}")
    for i in range(num_packets):
        protocol = random.choice(["TCP", "UDP"])
        source_ip = f"10.0.0.{random.randint(1, 254)}"
        send_packet(target_ip, target_port, protocol, source_ip=source_ip)
        time.sleep(random.uniform(0.5, 2.0))  # Random delay between packets

def simulate_ddos_attack(target_ip, target_port, attack_type="TCP", num_packets=100, fixed_source=False):
    """Simulate a DDoS attack on the controller"""
    print(f"Starting {attack_type} flood attack simulation with {num_packets} packets")
    
    # Use a fixed source IP if requested
    source_ip = "10.0.0.99" if fixed_source else None
    
    success_count = 0
    for i in range(num_packets):
        if send_packet(target_ip, target_port, attack_type, is_attack=True, source_ip=source_ip):
            success_count += 1
        
        if i % 10 == 0:  # Print status every 10 packets
            print(f"Sent {success_count}/{i+1} attack packets to {target_ip}")
        
        # Send packets rapidly to simulate attack
        time.sleep(0.01)

def main():
    # Target is the controller
    target_ip = "127.0.0.1"
    target_port = 6653  # OpenFlow port
    
    print("DDoS Detection & Mitigation System - Windows Test")
    print("================================================")
    print("1. First sending some normal traffic...")
    simulate_normal_traffic(target_ip, target_port, num_packets=10)
    
    print("\n2. Now simulating a TCP flood attack with fixed source IP...")
    time.sleep(2)
    simulate_ddos_attack(target_ip, target_port, attack_type="TCP", num_packets=100, fixed_source=True)
    
    print("\n3. Waiting to see if attack is detected...")
    time.sleep(5)
    
    print("\n4. Now simulating a UDP flood attack with random source IPs...")
    simulate_ddos_attack(target_ip, target_port, attack_type="UDP", num_packets=100, fixed_source=False)
    
    print("\nTest simulation completed.")

if __name__ == "__main__":
    main()