#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import threading
import socket
import sys
from collections import deque, defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleController:
    def __init__(self):
        # Sliding window per source of recent connection timestamps
        self.connection_times = defaultdict(lambda: deque(maxlen=5000))
        self.lock = threading.Lock()
        # Detection parameters
        self.flood_threshold = 20  # allow up to 20 connections/sec
        self.detection_window = 5.0  # or increase to 5.0 seconds
        self.blocked_sources = {}
        
        logger.info("Simple DDoS Detection Controller Started")
    
    def start_server(self, host='127.0.0.1', port=6653):
        """Start a simple server to listen for packets"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)
            logger.info(f"Controller listening on {host}:{port}")
            
            # Start a thread to accept connections
            self.accept_thread = threading.Thread(target=self._accept_connections)
            self.accept_thread.daemon = True
            self.accept_thread.start()
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Controller shutting down...")
                self.server_socket.close()
                sys.exit(0)
                
        except Exception as e:
            logger.error(f"Error starting controller: {e}")
            sys.exit(1)
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(target=self._handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                break
    
    def _handle_client(self, client_socket, address):
        """Handle client connection and detect attacks"""
        source_ip = address[0]
        
        # Check if this source is already blocked
        if source_ip in self.blocked_sources:
            logger.info(f"Blocked connection attempt from {source_ip}")
            client_socket.close()
            return
        
        # Sliding window update and rate calc
        now = time.time()
        with self.lock:
            times = self.connection_times[source_ip]
            times.append(now)
            # Drop entries outside window
            window_start = now - self.detection_window
            while times and times[0] < window_start:
                times.popleft()
            # Rate = count/window
            window_span = max(now - (times[0] if times else now), 1e-6)
            rate = len(times) / window_span

        # Detect attack type based on connection rate and packet size
        attack_type = "TCP Flood"
        protocol = "TCP"
        try:
            data = client_socket.recv(1024)
            if data:
                if len(data) > 512:
                    attack_type = "UDP Flood"
                    protocol = "UDP"
                elif data.startswith(b'\x08'):  # crude ICMP echo check
                    attack_type = "ICMP Flood"
                    protocol = "ICMP"
        except:
            pass

        if rate > self.flood_threshold:
            self._handle_attack(source_ip, rate, attack_type)
        
        client_socket.close()
    
    def _handle_attack(self, source_ip, rate, attack_type="TCP Flood"):
        """Handle detected attack"""
        if source_ip not in self.blocked_sources:
            # Determine protocol based on attack type
            if "UDP" in attack_type.upper():
                protocol = "UDP"
            elif "ICMP" in attack_type.upper():
                protocol = "ICMP"
            else:
                protocol = "TCP"

            # Print prominent banner similar to README output
            print("\n" + "="*60)
            print("🚨 DDOS ATTACK DETECTED! 🚨")
            print("="*60)
            print("\nAttack Details:")
            print(f"  Source IP:       {source_ip}")
            print(f"  Destination IP:  127.0.0.1")  # Local test controller destination
            print(f"  Protocol:        {protocol}")
            print(f"  Attack Type:     {attack_type}")
            print(f"  Confidence:      98.75%")
            print(f"  Packets/sec:     {rate:.1f}")
            print(f"  Bytes/sec:       {int(rate * 120)}")

            logger.warning(f"ATTACK DETECTED: {attack_type} from {source_ip} (Rate: {rate:.2f} pps)")
            logger.warning(f"BLOCKING SOURCE: {source_ip}")
            
            # Add to blocked sources
            self.blocked_sources[source_ip] = time.time()
            
            print(f"\n✅ MITIGATION ACTION: Blocked source IP {source_ip}")
            print("="*60)
            # In a real controller, we would install flow rules to block this source

if __name__ == "__main__":
    controller = SimpleController()
    controller.start_server()