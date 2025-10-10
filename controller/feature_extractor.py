#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import numpy as np
from collections import defaultdict
import time

class FeatureExtractor:
    """
    Extract features from network flows for DDoS attack detection
    """
    def __init__(self, flow_stats_interval=1, flow_timeout=10):
        """
        Initialize the feature extractor
        
        Args:
            flow_stats_interval: Interval to collect flow statistics (seconds)
            flow_timeout: Time after which a flow is considered expired (seconds)
        """
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'duration_sec': 0,
            'duration_nsec': 0,
            'last_seen': 0,
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'packet_size_mean': 0
        })
        self.flow_stats_interval = flow_stats_interval
        self.flow_timeout = flow_timeout
        self.last_collection_time = time.time()
        
    def extract_features(self, flow_stats):
        """
        Extract features from flow statistics
        
        Args:
            flow_stats: Flow statistics from Ryu controller
            
        Returns:
            DataFrame with extracted features
        """
        current_time = time.time()
        features = []
        
        # Process each flow
        for stat in flow_stats:
            match = stat.match
            
            # Create flow key
            if 'ipv4_src' in match and 'ipv4_dst' in match:
                flow_key = (
                    match.get('ipv4_src', ''), 
                    match.get('ipv4_dst', ''),
                    match.get('ip_proto', 0),
                    match.get('tcp_src', 0) if match.get('ip_proto', 0) == 6 else match.get('udp_src', 0),
                    match.get('tcp_dst', 0) if match.get('ip_proto', 0) == 6 else match.get('udp_dst', 0)
                )
                
                # Calculate time-based features
                packet_count = stat.packet_count
                byte_count = stat.byte_count
                duration_sec = stat.duration_sec
                duration_nsec = stat.duration_nsec
                
                # Convert duration to seconds
                duration = duration_sec + (duration_nsec / 1000000000.0)
                
                # Avoid division by zero
                if duration > 0:
                    packets_per_second = packet_count / duration
                    bytes_per_second = byte_count / duration
                    packet_size_mean = byte_count / packet_count if packet_count > 0 else 0
                else:
                    packets_per_second = 0
                    bytes_per_second = 0
                    packet_size_mean = 0
                
                # Update flow statistics
                self.flow_stats[flow_key] = {
                    'packet_count': packet_count,
                    'byte_count': byte_count,
                    'duration_sec': duration_sec,
                    'duration_nsec': duration_nsec,
                    'last_seen': current_time,
                    'packets_per_second': packets_per_second,
                    'bytes_per_second': bytes_per_second,
                    'packet_size_mean': packet_size_mean
                }
                
                # Extract protocol information
                ip_proto = match.get('ip_proto', 0)
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_proto, 'OTHER')
                
                # Create feature vector
                feature = {
                    'src_ip': match.get('ipv4_src', ''),
                    'dst_ip': match.get('ipv4_dst', ''),
                    'protocol': proto_name,
                    'src_port': match.get('tcp_src', match.get('udp_src', 0)),
                    'dst_port': match.get('tcp_dst', match.get('udp_dst', 0)),
                    'packet_count': packet_count,
                    'byte_count': byte_count,
                    'duration': duration,
                    'packets_per_second': packets_per_second,
                    'bytes_per_second': bytes_per_second,
                    'packet_size_mean': packet_size_mean
                }
                
                features.append(feature)
        
        # Clean up expired flows
        self._clean_expired_flows(current_time)
        self.last_collection_time = current_time
        
        # Convert to DataFrame
        if features:
            return pd.DataFrame(features)
        else:
            return pd.DataFrame()
    
    def _clean_expired_flows(self, current_time):
        """
        Remove expired flows from the flow statistics
        
        Args:
            current_time: Current time
        """
        expired_flows = []
        for flow_key, stats in self.flow_stats.items():
            if current_time - stats['last_seen'] > self.flow_timeout:
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            del self.flow_stats[flow_key]
    
    def prepare_features_for_prediction(self, df):
        """
        Prepare features for prediction
        
        Args:
            df: DataFrame with extracted features
            
        Returns:
            DataFrame with features ready for prediction
        """
        if df.empty:
            return None
        
        # Select and normalize features for prediction
        features = df[['packets_per_second', 'bytes_per_second', 'packet_size_mean', 'duration', 'protocol']]
        
        # One-hot encode protocol
        features = pd.get_dummies(features, columns=['protocol'], prefix=['protocol'])
        
        # Ensure all protocol columns exist
        for proto in ['protocol_ICMP', 'protocol_TCP', 'protocol_UDP', 'protocol_OTHER']:
            if proto not in features.columns:
                features[proto] = 0
                
        return features
    
    def save_to_csv(self, df, filename='traffic_data.csv'):
        """
        Save extracted features to CSV file
        
        Args:
            df: DataFrame with extracted features
            filename: Output filename
        """
        if not df.empty:
            df.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename), index=False)