#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import os
from datetime import datetime

class PacketLogger:
    """
    Class for logging packet information to CSV files.
    """
    def __init__(self, log_dir='../logs', log_file='packet_log.csv'):
        """
        Initializes the packet logger.
        
        Args:
            log_dir: Directory to store log files.
            log_file: Name of the log file.
        """
        self.log_dir = log_dir
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Set log file path
        self.log_file = os.path.join(log_dir, log_file)
        
        # Initialize the CSV file with headers if it doesn't exist
        self.columns = [
            'timestamp', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 
            'protocol', 'src_port', 'dst_port', 'packet_size', 
            'flags', 'status', 'reason'
        ]
        
        if not os.path.exists(self.log_file):
            pd.DataFrame(columns=self.columns).to_csv(self.log_file, index=False)
            print(f"Packet logging initialized. Created new log file: {self.log_file}")
        else:
            print(f"Packet logging initialized. Appending to existing log file: {self.log_file}")

    def log_packet(self, pkt_data, status='normal', reason=None):
        """
        Logs a packet to the CSV file.
        
        Args:
            pkt_data: Dictionary containing packet information.
            status: Packet status (e.g., 'normal', 'blocked').
            reason: Reason for the packet's status.
        """
        # Create a DataFrame with the packet data
        df = pd.DataFrame([{
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'src_mac': pkt_data.get('src_mac', 'unknown'),
            'dst_mac': pkt_data.get('dst_mac', 'unknown'),
            'src_ip': pkt_data.get('src_ip', 'unknown'),
            'dst_ip': pkt_data.get('dst_ip', 'unknown'),
            'protocol': pkt_data.get('protocol', 0),
            'src_port': pkt_data.get('src_port', 0),
            'dst_port': pkt_data.get('dst_port', 0),
            'packet_size': pkt_data.get('packet_size', 0),
            'flags': pkt_data.get('flags', ''),
            'status': status,
            'reason': reason if reason else ''
        }])
        
        # Append to the CSV file
        df.to_csv(self.log_file, mode='a', header=False, index=False)

    def get_logs(self):
        """
        Retrieves all logs from the log file.
        
        Returns:
            A pandas DataFrame containing the logs.
        """
        try:
            return pd.read_csv(self.log_file)
        except FileNotFoundError:
            return pd.DataFrame(columns=self.columns)
        return pd.DataFrame(columns=self.columns)