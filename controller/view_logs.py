#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import os
import sys
import glob
from datetime import datetime

def list_log_files(log_dir='../logs'):
    """List all available log files"""
    if not os.path.exists(log_dir):
        print(f"Log directory {log_dir} does not exist.")
        return []
    
    log_files = glob.glob(os.path.join(log_dir, 'packet_log.csv'))
    return sorted(log_files)

def view_logs(log_file=None, filter_status=None):
    """
    View packet logs with optional filtering
    
    Args:
        log_file: Path to specific log file (if None, uses most recent)
        filter_status: Filter by status ('normal', 'blocked', or None for all)
    """
    log_dir = '../logs'
    # Get log files
    log_files = list_log_files(log_dir)
    
    if not log_files and not log_file:
        print("No log files found.")
        return
    
    # Use specified log file or most recent
    if log_file:
        # If a file is specified and not an absolute path, assume it's in the log dir
        if not os.path.isabs(log_file):
            log_file = os.path.join(log_dir, log_file)
    else:
        log_file = log_files[-1]  # Most recent log file
    
    # Read the log file
    try:
        df = pd.read_csv(log_file)
        
        # Apply filter if specified
        if filter_status:
            df = df[df['status'] == filter_status]
        
        # Print summary
        total_packets = len(df)
        normal_packets = len(df[df['status'] == 'normal'])
        blocked_packets = len(df[df['status'] == 'blocked'])
        
        print(f"\nLog File: {os.path.basename(log_file)}")
        print(f"Total Packets: {total_packets}")
        print(f"Normal Packets: {normal_packets}")
        print(f"Blocked Packets: {blocked_packets}")
        
        # Display the logs
        if len(df) > 0:
            print("\nPacket Logs:")
            pd.set_option('display.max_columns', None)
            pd.set_option('display.width', None)
            print(df)
        else:
            print("\nNo packets found with the specified filter.")
    
    except FileNotFoundError:
        print(f"Log file {log_file} does not exist.")
        return
    except pd.errors.EmptyDataError:
        print(f"Log file {log_file} is empty.")
        return
    except Exception as e:
        print(f"Error reading log file: {e}")

def main():
    """Main function to handle command line arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(description='View packet logs')
    parser.add_argument('--file', help='Specific log file to view')
    parser.add_argument('--status', choices=['normal', 'blocked'], 
                        help='Filter by packet status (normal or blocked)')
    parser.add_argument('--list', action='store_true', 
                        help='List all available log files')
    
    args = parser.parse_args()
    
    if args.list:
        log_files = list_log_files()
        if log_files:
            print("Available log files:")
            for i, file in enumerate(log_files):
                print(f"{i+1}. {os.path.basename(file)}")
        else:
            print("No log files found.")
    else:
        view_logs(args.file, args.status)

if __name__ == "__main__":
    main()