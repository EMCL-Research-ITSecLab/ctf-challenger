#!/usr/bin/env python3
"""
Flow Statistics Analyzer

Analyzes flow duration statistics from PCAP feature extraction results
to assess flow quality and characteristics.
"""

import csv
import sys
from typing import List, Dict


class FlowStatsAnalyzer:
    """Analyzer for flow duration and packet statistics."""
    
    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.flows: List[Dict[str, str]] = []
        
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
    
    def analyze_durations(self) -> None:
        """Analyze flow duration statistics."""
        durations = []
        packets = []
        bytes_total = []
        
        for flow in self.flows:
            try:
                duration_ms = float(flow.get('FLOW_DURATION_MILLISECONDS', 0))
                durations.append(duration_ms)
                
                in_pkts = int(flow.get('IN_PKTS', 0))
                out_pkts = int(flow.get('OUT_PKTS', 0))
                total_pkts = in_pkts + out_pkts
                packets.append(total_pkts)
                
                in_bytes = int(flow.get('IN_BYTES', 0))
                out_bytes = int(flow.get('OUT_BYTES', 0))
                total_bytes = in_bytes + out_bytes
                bytes_total.append(total_bytes)
                
            except (ValueError, TypeError):
                continue
        
        if not durations:
            print("✗ No valid flow durations found!")
            return
        
        print("=" * 80)
        print("FLOW DURATION STATISTICS")
        print("=" * 80)
        
        durations_sec = [d / 1000 for d in durations]
        
        avg_duration = sum(durations_sec) / len(durations_sec)
        min_duration = min(durations_sec)
        max_duration = max(durations_sec)
        
        print(f"\nTotal Flows: {len(durations)}")
        print(f"\nDuration (seconds):")
        print(f"  Average:  {avg_duration:.3f}s")
        print(f"  Minimum:  {min_duration:.3f}s")
        print(f"  Maximum:  {max_duration:.3f}s")
        print(f"  Median:   {self.median(durations_sec):.3f}s")
        
        self.print_duration_distribution(durations_sec)
        
        print("\n" + "=" * 80)
        print("PACKET STATISTICS")
        print("=" * 80)
        
        if packets:
            avg_pkts = sum(packets) / len(packets)
            print(f"\nPackets per flow:")
            print(f"  Average:  {avg_pkts:.1f}")
            print(f"  Minimum:  {min(packets)}")
            print(f"  Maximum:  {max(packets)}")
            print(f"  Median:   {self.median(packets):.1f}")
            print(f"  Total:    {sum(packets)}")
        
        print("\n" + "=" * 80)
        print("BYTES STATISTICS")
        print("=" * 80)
        
        if bytes_total:
            avg_bytes = sum(bytes_total) / len(bytes_total)
            print(f"\nBytes per flow:")
            print(f"  Average:  {avg_bytes:.1f} ({self.format_bytes(avg_bytes)})")
            print(f"  Minimum:  {min(bytes_total)} ({self.format_bytes(min(bytes_total))})")
            print(f"  Maximum:  {max(bytes_total)} ({self.format_bytes(max(bytes_total))})")
            print(f"  Median:   {self.median(bytes_total):.1f} ({self.format_bytes(self.median(bytes_total))})")
            print(f"  Total:    {sum(bytes_total)} ({self.format_bytes(sum(bytes_total))})")
        
        print("\n" + "=" * 80)
        print("FLOW QUALITY ASSESSMENT")
        print("=" * 80)
        
        self.assess_flow_quality(durations_sec, packets)
    
    def print_duration_distribution(self, durations: List[float]) -> None:
        """Print distribution of flow durations."""
        print(f"\nDuration Distribution:")
        
        buckets = [
            (0, 0.001, "< 1ms (very short)"),
            (0.001, 0.01, "1-10ms (short)"),
            (0.01, 0.1, "10-100ms"),
            (0.1, 1, "100ms-1s"),
            (1, 10, "1-10s"),
            (10, 60, "10-60s"),
            (60, 300, "1-5min"),
            (300, float('inf'), "> 5min (long)")
        ]
        
        for min_val, max_val, label in buckets:
            count = sum(1 for d in durations if min_val <= d < max_val)
            pct = (count / len(durations) * 100) if durations else 0
            bar = "█" * int(pct / 2)
            print(f"  {label:20s}: {count:5d} ({pct:5.1f}%) {bar}")
    
    def assess_flow_quality(self, durations: List[float], packets: List[int]) -> None:
        """Assess overall flow quality."""
        issues = []
        good_points = []
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        very_short = sum(1 for d in durations if d < 0.001)
        very_short_pct = (very_short / len(durations) * 100) if durations else 0
        
        single_packet = sum(1 for p in packets if p <= 1)
        single_packet_pct = (single_packet / len(packets) * 100) if packets else 0
        
        if very_short_pct > 50:
            issues.append(f"⚠ {very_short_pct:.1f}% of flows are < 1ms (possibly fragmented)")
        elif very_short_pct > 20:
            issues.append(f"⚠ {very_short_pct:.1f}% of flows are < 1ms (consider adjusting flow timeout)")
        else:
            good_points.append(f"✓ Only {very_short_pct:.1f}% very short flows (< 1ms)")
        
        if single_packet_pct > 30:
            issues.append(f"⚠ {single_packet_pct:.1f}% of flows have ≤1 packet (many incomplete flows)")
        else:
            good_points.append(f"✓ Only {single_packet_pct:.1f}% single-packet flows")
        
        if avg_duration < 0.1:
            issues.append(f"⚠ Average flow duration very short ({avg_duration:.3f}s)")
        elif avg_duration > 10:
            good_points.append(f"✓ Good average flow duration ({avg_duration:.3f}s)")
        else:
            good_points.append(f"✓ Reasonable average flow duration ({avg_duration:.3f}s)")
        
        avg_pkts = sum(packets) / len(packets) if packets else 0
        if avg_pkts < 2:
            issues.append(f"⚠ Very low average packets per flow ({avg_pkts:.1f})")
        elif avg_pkts >= 10:
            good_points.append(f"✓ Good average packets per flow ({avg_pkts:.1f})")
        else:
            good_points.append(f"✓ Acceptable packets per flow ({avg_pkts:.1f})")
        
        print("\nPositive indicators:")
        for point in good_points:
            print(f"  {point}")
        
        if issues:
            print("\nPotential issues:")
            for issue in issues:
                print(f"  {issue}")
        
        print("\n" + "-" * 80)
        
        if len(good_points) >= 3 and len(issues) <= 1:
            print("✓✓✓ FLOWS LOOK GOOD ✓✓✓")
            print("\nFlow extraction quality appears to be good for analysis!")
        elif len(issues) >= 3:
            print("⚠⚠⚠ FLOW QUALITY CONCERNS ⚠⚠⚠")
            print("\nConsider adjusting flow timeout parameters or check PCAP quality.")
        else:
            print("✓ FLOWS ARE ACCEPTABLE")
            print("\nFlow quality is reasonable for most analysis tasks.")
    
    @staticmethod
    def median(values: List[float]) -> float:
        """Calculate median value."""
        if not values:
            return 0
        sorted_values = sorted(values)
        n = len(sorted_values)
        if n % 2 == 0:
            return (sorted_values[n//2 - 1] + sorted_values[n//2]) / 2
        else:
            return sorted_values[n//2]
    
    @staticmethod
    def format_bytes(bytes_val: float) -> str:
        """Format bytes in human-readable form."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"


def main():
    if len(sys.argv) < 2:
        print("Usage: python flow_stats.py <features.csv>")
        print("\nExample:")
        print("  python flow_stats.py features.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    analyzer = FlowStatsAnalyzer(csv_file)
    
    if not analyzer.load_csv():
        sys.exit(1)
    
    analyzer.analyze_durations()
    
    print("\n" + "=" * 80)
    print("Analysis completed!")
    print("=" * 80)


if __name__ == '__main__':
    main()
