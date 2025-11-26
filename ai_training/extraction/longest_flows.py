#!/usr/bin/env python3
"""
Flow Inspector

Inspects and displays detailed information about the longest/largest flows
in PCAP feature extraction results.
"""

import csv
import sys
from typing import List, Dict, Any


class FlowInspector:
    """Inspector for detailed flow analysis."""
    
    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.flows: List[Dict[str, Any]] = []
        
    def load_csv(self) -> bool:
        """Load CSV file."""
        print(f"Loading CSV: {self.csv_file}")
        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.flows = list(reader)
            print(f"✓ {len(self.flows)} flows loaded\n")
            return True
        except Exception as e:
            print(f"✗ Error loading file: {e}")
            return False
    
    def show_longest_flows(self, n: int = 10) -> None:
        """Display the N longest flows by duration."""
        print("=" * 120)
        print(f"TOP {n} LONGEST FLOWS (by duration)")
        print("=" * 120)
        
        flows_with_duration = []
        for flow in self.flows:
            try:
                duration = float(flow.get('FLOW_DURATION_MILLISECONDS', 0))
                flows_with_duration.append((duration, flow))
            except (ValueError, TypeError):
                continue
        
        flows_with_duration.sort(reverse=True, key=lambda x: x[0])
        
        for i, (duration_ms, flow) in enumerate(flows_with_duration[:n], 1):
            duration_s = duration_ms / 1000
            duration_h = duration_s / 3600
            duration_m = (duration_s % 3600) / 60
            duration_sec = duration_s % 60
            
            src_ip = flow.get('IPV4_SRC_ADDR', 'N/A')
            dst_ip = flow.get('IPV4_DST_ADDR', 'N/A')
            src_port = flow.get('L4_SRC_PORT', 'N/A')
            dst_port = flow.get('L4_DST_PORT', 'N/A')
            protocol = flow.get('PROTOCOL', 'N/A')
            
            in_pkts = flow.get('IN_PKTS', 0)
            out_pkts = flow.get('OUT_PKTS', 0)
            in_bytes = flow.get('IN_BYTES', 0)
            out_bytes = flow.get('OUT_BYTES', 0)
            
            try:
                total_pkts = int(in_pkts) + int(out_pkts)
                total_bytes = int(in_bytes) + int(out_bytes)
            except (ValueError, TypeError):
                total_pkts = 0
                total_bytes = 0
            
            proto_name = self.get_protocol_name(protocol)
            
            print(f"\n#{i} Flow:")
            print(f"  Duration:     {duration_s:.3f}s ({int(duration_h)}h {int(duration_m)}m {duration_sec:.1f}s)")
            print(f"  Source:       {src_ip}:{src_port}")
            print(f"  Destination:  {dst_ip}:{dst_port}")
            print(f"  Protocol:     {proto_name} ({protocol})")
            print(f"  Packets:      {total_pkts} (IN: {in_pkts}, OUT: {out_pkts})")
            print(f"  Bytes:        {self.format_bytes(total_bytes)} (IN: {self.format_bytes(int(in_bytes))}, OUT: {self.format_bytes(int(out_bytes))})")
            
            if total_pkts > 0 and duration_s > 0:
                pps = total_pkts / duration_s
                bps = total_bytes * 8 / duration_s
                print(f"  Rate:         {pps:.2f} pkt/s, {self.format_bits(bps)}/s")
    
    def show_largest_flows(self, n: int = 10) -> None:
        """Display the N largest flows by bytes."""
        print("\n" + "=" * 120)
        print(f"TOP {n} LARGEST FLOWS (by bytes)")
        print("=" * 120)
        
        flows_with_bytes = []
        for flow in self.flows:
            try:
                in_bytes = int(flow.get('IN_BYTES', 0))
                out_bytes = int(flow.get('OUT_BYTES', 0))
                total_bytes = in_bytes + out_bytes
                flows_with_bytes.append((total_bytes, flow))
            except (ValueError, TypeError):
                continue
        
        flows_with_bytes.sort(reverse=True, key=lambda x: x[0])
        
        for i, (total_bytes, flow) in enumerate(flows_with_bytes[:n], 1):
            duration_ms = float(flow.get('FLOW_DURATION_MILLISECONDS', 0))
            duration_s = duration_ms / 1000
            
            src_ip = flow.get('IPV4_SRC_ADDR', 'N/A')
            dst_ip = flow.get('IPV4_DST_ADDR', 'N/A')
            src_port = flow.get('L4_SRC_PORT', 'N/A')
            dst_port = flow.get('L4_DST_PORT', 'N/A')
            protocol = flow.get('PROTOCOL', 'N/A')
            
            in_pkts = flow.get('IN_PKTS', 0)
            out_pkts = flow.get('OUT_PKTS', 0)
            in_bytes = int(flow.get('IN_BYTES', 0))
            out_bytes = int(flow.get('OUT_BYTES', 0))
            
            try:
                total_pkts = int(in_pkts) + int(out_pkts)
            except (ValueError, TypeError):
                total_pkts = 0
            
            proto_name = self.get_protocol_name(protocol)
            
            print(f"\n#{i} Flow:")
            print(f"  Bytes:        {self.format_bytes(total_bytes)} (IN: {self.format_bytes(in_bytes)}, OUT: {self.format_bytes(out_bytes)})")
            print(f"  Source:       {src_ip}:{src_port}")
            print(f"  Destination:  {dst_ip}:{dst_port}")
            print(f"  Protocol:     {proto_name} ({protocol})")
            print(f"  Packets:      {total_pkts} (IN: {in_pkts}, OUT: {out_pkts})")
            print(f"  Duration:     {duration_s:.3f}s")
            
            if total_pkts > 0:
                avg_pkt_size = total_bytes / total_pkts
                print(f"  Avg Pkt Size: {avg_pkt_size:.0f} bytes")
    
    def show_most_packets(self, n: int = 10) -> None:
        """Display the N flows with most packets."""
        print("\n" + "=" * 120)
        print(f"TOP {n} FLOWS WITH MOST PACKETS")
        print("=" * 120)
        
        flows_with_packets = []
        for flow in self.flows:
            try:
                in_pkts = int(flow.get('IN_PKTS', 0))
                out_pkts = int(flow.get('OUT_PKTS', 0))
                total_pkts = in_pkts + out_pkts
                flows_with_packets.append((total_pkts, flow))
            except (ValueError, TypeError):
                continue
        
        flows_with_packets.sort(reverse=True, key=lambda x: x[0])
        
        for i, (total_pkts, flow) in enumerate(flows_with_packets[:n], 1):
            src_ip = flow.get('IPV4_SRC_ADDR', 'N/A')
            dst_ip = flow.get('IPV4_DST_ADDR', 'N/A')
            src_port = flow.get('L4_SRC_PORT', 'N/A')
            dst_port = flow.get('L4_DST_PORT', 'N/A')
            protocol = flow.get('PROTOCOL', 'N/A')
            
            duration_ms = float(flow.get('FLOW_DURATION_MILLISECONDS', 0))
            duration_s = duration_ms / 1000
            
            in_bytes = int(flow.get('IN_BYTES', 0))
            out_bytes = int(flow.get('OUT_BYTES', 0))
            total_bytes = in_bytes + out_bytes
            
            proto_name = self.get_protocol_name(protocol)
            
            print(f"\n#{i} Flow:")
            print(f"  Packets:      {total_pkts}")
            print(f"  Source:       {src_ip}:{src_port}")
            print(f"  Destination:  {dst_ip}:{dst_port}")
            print(f"  Protocol:     {proto_name} ({protocol})")
            print(f"  Duration:     {duration_s:.3f}s")
            print(f"  Bytes:        {self.format_bytes(total_bytes)}")
    
    @staticmethod
    def get_protocol_name(protocol: str) -> str:
        """Get protocol name from number."""
        proto_map = {
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP',
            '47': 'GRE',
            '50': 'ESP',
            '51': 'AH'
        }
        return proto_map.get(str(protocol), 'Unknown')
    
    @staticmethod
    def format_bytes(bytes_val: float) -> str:
        """Format bytes in human-readable form."""
        try:
            bytes_val = float(bytes_val)
        except (ValueError, TypeError):
            return "0 B"
            
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    @staticmethod
    def format_bits(bits_val: float) -> str:
        """Format bits per second in human-readable form."""
        for unit in ['bps', 'Kbps', 'Mbps', 'Gbps']:
            if bits_val < 1000.0:
                return f"{bits_val:.2f} {unit}"
            bits_val /= 1000.0
        return f"{bits_val:.2f} Tbps"


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python flow_inspector.py <features.csv> [--top N]")
        print("\nExamples:")
        print("  python flow_inspector.py features.csv")
        print("  python flow_inspector.py features.csv --top 20")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    top_n = 10
    
    if '--top' in sys.argv:
        try:
            top_n = int(sys.argv[sys.argv.index('--top') + 1])
        except (ValueError, IndexError):
            print("Invalid --top value, using default (10)")
    
    inspector = FlowInspector(csv_file)
    
    if not inspector.load_csv():
        sys.exit(1)
    
    inspector.show_longest_flows(top_n)
    inspector.show_largest_flows(top_n)
    inspector.show_most_packets(top_n)
    
    print("\n" + "=" * 120)
    print("Inspection completed!")
    print("=" * 120)


if __name__ == '__main__':
    main()
