import socket
import time
import random

def simulate_normal_traffic(target_ip, target_port, num_packets=10):
    print(f"Sending {num_packets} normal TCP packets to {target_ip}:{target_port}")
    for i in range(num_packets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.sendall(b"Normal traffic simulation")
            s.close()
            print(f"Sent TCP packet to {target_ip}:{target_port}")
            time.sleep(random.uniform(0.5, 2.0))
        except Exception as e:
            print(f"Error sending packet: {e}")

def simulate_ddos_attack(target_ip, target_port, attack_type="SYN", num_packets=50):
    print(f"Starting {attack_type} flood attack simulation with {num_packets} packets")
    for i in range(num_packets):
        try:
            if attack_type == "UDP":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b"A"*64, (target_ip, target_port))
                s.close()
            else:  # TCP SYN flood (just open and close connections rapidly)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    s.connect((target_ip, target_port))
                except Exception:
                    pass
                s.close()
            if i % 10 == 0:
                print(f"Sent {i+1}/{num_packets} attack packets to {target_ip}")
            time.sleep(0.01)
        except Exception as e:
            print(f"Error sending packet: {e}")

def main():
    target_ip = "127.0.0.1"  # Or your controller's LAN IP
    target_port = 6653

    print("DDoS Detection & Mitigation System - Test Simulation")
    print("====================================================")
    print("1. First sending some normal traffic...")
    simulate_normal_traffic(target_ip, target_port, num_packets=20)

    print("\n2. Now simulating a SYN flood attack...")
    time.sleep(2)
    simulate_ddos_attack(target_ip, target_port, attack_type="SYN", num_packets=50)

    print("\n3. Waiting to see if attack is detected...")
    time.sleep(5)

    print("\n4. Now simulating a UDP flood attack...")
    simulate_ddos_attack(target_ip, target_port, attack_type="UDP", num_packets=50)

    print("\nTest simulation completed.")

if __name__ == "__main__":
    main()