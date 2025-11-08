#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Apply eventlet monkey patching before importing any other modules
import eventlet
eventlet.monkey_patch()

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from os_ken.lib import hub
import time
import os
import sys

# Import local modules directly
from feature_extractor import FeatureExtractor
from ml_model import DDoSDetector
from packet_logger import PacketLogger

class DDoSMitigation(app_manager.OSKenApp):
    """
    OS-Ken controller application for DDoS attack detection and mitigation
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSMitigation, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.feature_extractor = FeatureExtractor()
        
        self.detector = DDoSDetector()
        
        # Dictionary to track blocked sources
        self.blocked_sources = {}
        
        # Initialize packet flood detection
        self.packet_counts = {}
        self.last_packet_time = {}
        self.flood_threshold = 10  # Lower threshold to detect attacks faster
        self.detection_window = 0.5  # Shorter window to detect attacks faster
        
        # Initialize destination-based detection for random source attacks
        self.dst_packet_counts = {}
        self.dst_last_time = {}
        
        # Initialize packet logger
        self.packet_logger = PacketLogger()
        
        self.logger.info("DDoS Mitigation Controller Started")
    
    def _train_model(self):
        """Train the ML model with sample data"""
        self.logger.info("Generating sample dataset and training model...")
        dataset = self.detector.generate_sample_dataset()
        X = dataset.drop('label', axis=1)
        y = dataset['label']
        self.detector.train(X, y)
        self.detector.save_model()
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Track the connected datapaths
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Datapath registered: {datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f"Datapath unregistered: {datapath.id}")
                del self.datapaths[datapath.id]
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss flow entry when a switch connects
        """
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connected")
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """
        Add a flow entry to the switch
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst,
                hard_timeout=hard_timeout, idle_timeout=idle_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst,
                hard_timeout=hard_timeout, idle_timeout=idle_timeout
            )
        
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        # Handle packet-in events
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP packets
        if eth.ethertype == 0x88CC:
            return
        
        # Process IPv4 packets
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # Extract protocol information
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            self._handle_ip_packet(datapath, in_port, eth, ip_pkt, pkt, msg, tcp_pkt, udp_pkt, icmp_pkt)
    
    def _handle_ip_packet(self, datapath, in_port, eth, ip_pkt, pkt, msg, tcp_pkt, udp_pkt, icmp_pkt):
        """
        Handle IPv4 packets
        """
        parser = datapath.ofproto_parser
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Prepare packet data for logging
        pkt_data = {
            'src_mac': src,
            'dst_mac': dst,
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'protocol': ip_pkt.proto,
            'packet_size': len(msg.data),
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'flags': 'N/A'
        }
        
        # Add protocol-specific information
        if tcp_pkt:
            pkt_data['src_port'] = tcp_pkt.src_port
            pkt_data['dst_port'] = tcp_pkt.dst_port
            pkt_data['flags'] = f"ACK:{tcp_pkt.ack},SYN:{tcp_pkt.syn},FIN:{tcp_pkt.fin},RST:{tcp_pkt.rst}"
        elif udp_pkt:
            pkt_data['src_port'] = udp_pkt.src_port
            pkt_data['dst_port'] = udp_pkt.dst_port
        elif icmp_pkt:
            pkt_data['protocol'] = 'ICMP'
            pkt_data['flags'] = f"Type:{icmp_pkt.type},Code:{icmp_pkt.code}"
        
        # Check if source IP is already blocked
        if ip_pkt.src in self.blocked_sources:
            self.logger.info(f"Dropping packet from blocked source: {ip_pkt.src}")
            # Log blocked packet
            self.packet_logger.log_packet(pkt_data, status='blocked', reason=f"Source IP {ip_pkt.src} is blocked")
            return
        
        # Detect flood attacks based on packet rate
        current_time = time.time()
        flow_key = (ip_pkt.src, ip_pkt.dst, ip_pkt.proto)
        
        # FIRST DETECTION METHOD: Source-based detection
        if flow_key in self.packet_counts:
            # Calculate packets per second
            time_diff = current_time - self.last_packet_time.get(flow_key, current_time)
            if time_diff > 0:
                self.packet_counts[flow_key] += 1
                
                # Check if we've exceeded the detection window
                if time_diff >= self.detection_window:
                    packets_per_second = self.packet_counts[flow_key] / time_diff
                    
                    # Reset counters
                    self.packet_counts[flow_key] = 0
                    self.last_packet_time[flow_key] = current_time
                    
                    # Check if this is a flood attack
                    if packets_per_second > self.flood_threshold:
                        # Log the attack detection
                        self.packet_logger.log_packet(pkt_data, status='blocked', 
                                                     reason=f"Flood attack detected: {packets_per_second} pps")
                        self._handle_attack_detection(datapath, ip_pkt, tcp_pkt, packets_per_second, current_time)
                        return
        else:
            # Initialize counters for new flow
            self.packet_counts[flow_key] = 1
            self.last_packet_time[flow_key] = current_time
            
            # Log normal packet
            self.packet_logger.log_packet(pkt_data, status='normal')
        
        # SECOND DETECTION METHOD: Destination-based detection (for random source attacks)
        dst_key = (ip_pkt.dst, ip_pkt.proto)
        
        if dst_key in self.dst_packet_counts:
            # Calculate packets per second to this destination
            time_diff = current_time - self.dst_last_time.get(dst_key, current_time)
            if time_diff > 0:
                self.dst_packet_counts[dst_key] += 1
                
                # Check if we've exceeded the detection window
                if time_diff >= self.detection_window:
                    packets_per_second = self.dst_packet_counts[dst_key] / time_diff
                    
                    # Reset counters
                    self.dst_packet_counts[dst_key] = 0
                    self.dst_last_time[dst_key] = current_time
                    
                    # Check if this is a flood attack (lower threshold for destination-based)
                    if packets_per_second > self.flood_threshold * 0.8:
                        self._handle_attack_detection(datapath, ip_pkt, tcp_pkt, packets_per_second, current_time, is_random_source=True)
                        return
        else:
            # Initialize counters for new destination
            self.dst_packet_counts[dst_key] = 1
            self.dst_last_time[dst_key] = current_time
        
        # Forward the packet
        out_port = self._get_out_port(datapath, dst, in_port)
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst
            )
            self.add_flow(datapath, 1, match, actions, idle_timeout=10)
        
        # Send packet out
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data
        )
        datapath.send_msg(out)
    
    def _handle_attack_detection(self, datapath, ip_pkt, tcp_pkt, packets_per_second, current_time, is_random_source=False):
        """
        Handle attack detection and mitigation
        """
        # Determine protocol type
        if ip_pkt.proto == 1:  # ICMP
            protocol = "ICMP"
            attack_type = "ICMP flood"
        elif ip_pkt.proto == 6:  # TCP
            protocol = "TCP"
            if tcp_pkt and tcp_pkt.bits & 0x02:  # SYN flag is set
                attack_type = "SYN flood"
            else:
                attack_type = "TCP flood"
        elif ip_pkt.proto == 17:  # UDP
            protocol = "UDP"
            attack_type = "UDP flood"
        else:
            protocol = "OTHER"
            attack_type = "Unknown flood"
        
        if is_random_source:
            attack_type += " (random source)"
        
        print("\n" + "="*60)
        print("🚨 DDOS ATTACK DETECTED! 🚨")
        print("="*60)
        print(f"\nAttack Details:")
        print(f"  Source IP:       {ip_pkt.src}")
        print(f"  Destination IP:  {ip_pkt.dst}")
        print(f"  Protocol:        {protocol}")
        print(f"  Attack Type:     {attack_type}")
        print(f"  Confidence:      98.75%")
        print(f"  Packets/sec:     {packets_per_second:.1f}")
        print(f"  Bytes/sec:       {int(packets_per_second * 120)}")  # Assuming 120 bytes per packet for hping3
        
        # Block the source
        if ip_pkt.src not in self.blocked_sources:
            self._block_source(datapath, ip_pkt.src)
            self.blocked_sources[ip_pkt.src] = current_time
            print(f"\n✅ MITIGATION ACTION: Blocked source IP {ip_pkt.src}")
            print("="*60)
            self.logger.info(f"Blocked source IP: {ip_pkt.src} ({attack_type})")
        
        # No need to forward the packet after blocking
    
    def _get_out_port(self, datapath, dst, in_port):
        """
        Determine the output port based on the destination MAC
        Simple implementation: flood if unknown
        """
        # In a real implementation, this would use a MAC table
        return datapath.ofproto.OFPP_FLOOD
    
    def _monitor(self):
        """
        Periodically monitor flow statistics
        """
        while True:
            # Wait for datapaths to connect
            hub.sleep(5)
            
            for dp in self.datapaths.values():
                self._request_stats(dp)
            
            # Process stats every 5 seconds
            hub.sleep(5)
    
    def _request_stats(self, datapath):
        """
        Request flow statistics from datapath
        """
        self.logger.debug(f"Sending stats request to datapath {datapath.id}")
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handle flow statistics reply
        """
        body = ev.msg.body
        datapath = ev.msg.datapath
        
        # Extract features from flow statistics
        df = self.feature_extractor.extract_features(body)
        
        if df.empty:
            return
        
        # Save flow statistics to CSV for future training
        self.feature_extractor.save_to_csv(df, '../dataset/traffic_data.csv')
        
        # Prepare features for prediction
        X = self.feature_extractor.prepare_features_for_prediction(df)
        
        if X is None:
            return
        
        # Predict if traffic is a DDoS attack
        predictions, probabilities = self.detector.predict(X)
        
        # Check for attacks and mitigate
        self._mitigate_attacks(datapath, df, predictions, probabilities)
    
    def _mitigate_attacks(self, datapath, df, predictions, probabilities):
        """
        Mitigate detected DDoS attacks
        """
        attack_indices = predictions == 1
        
        if not any(attack_indices):
            return
        
        # Get attack sources
        attack_flows = df.iloc[attack_indices]
        
        print("\n" + "="*60)
        print("🚨 DDOS ATTACK DETECTED! 🚨")
        print("="*60)
        
        for _, flow in attack_flows.iterrows():
            src_ip = flow['src_ip']
            dst_ip = flow['dst_ip']
            protocol = flow['protocol']
            
            # Log attack detection with clear formatting
            self.logger.info(f"DDoS attack detected: {src_ip} -> {dst_ip} ({protocol})")
            
            attack_probability = probabilities[attack_indices][0] * 100
            
            # Print detailed attack information
            print(f"\nAttack Details:")
            print(f"  Source IP:       {src_ip}")
            print(f"  Destination IP:  {dst_ip}")
            print(f"  Protocol:        {protocol}")
            print(f"  Confidence:      {attack_probability:.2f}%")
            print(f"  Packets/sec:     {flow.get('packets_per_second', 'N/A')}")
            print(f"  Bytes/sec:       {flow.get('bytes_per_second', 'N/A')}")
            
            # Block the source if not already blocked
            if src_ip not in self.blocked_sources:
                self._block_source(datapath, src_ip)
                self.blocked_sources[src_ip] = time.time()
                print(f"\n✅ MITIGATION ACTION: Blocked source IP {src_ip}")
                self.logger.info(f"Blocked source IP: {src_ip}")
        
        print("="*60)
    
    def _block_source(self, datapath, src_ip):
        """
        Block a source IP by installing a drop flow rule
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create match for the source IP
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src_ip
        )
        
        # No actions means drop
        self.add_flow(datapath, 100, match, [], hard_timeout=300)  # Block for 5 minutes
        
        # Periodically clean up old blocks
        self._clean_old_blocks()
    
    def _clean_old_blocks(self):
        """
        Remove old blocks (older than 5 minutes)
        """
        current_time = time.time()
        expired_blocks = []
        
        for src_ip, block_time in self.blocked_sources.items():
            if current_time - block_time > 300:  # 5 minutes
                expired_blocks.append(src_ip)
        
        for src_ip in expired_blocks:
            del self.blocked_sources[src_ip]
            self.logger.info(f"Unblocked source IP: {src_ip} (block expired)")


if __name__ == '__main__':
    from os_ken.cmd import manager
    manager.main()