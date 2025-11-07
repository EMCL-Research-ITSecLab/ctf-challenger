#!/usr/bin/env python3
"""
CSV Feature Validator

Validates PCAP feature extraction results by analyzing feature completeness,
data quality, and identifying problematic columns.
"""

import csv
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any


class CSVValidator:
    """Validator for PCAP feature extraction CSV files."""

    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.rows: List[Dict[str, str]] = []
        self.headers: List[str] = []
        self.stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'zero_count': 0,
            'non_zero_count': 0,
            'empty_count': 0,
            'unique_values': set(),
            'min': float('inf'),
            'max': float('-inf'),
            'sum': 0
        })

    def load_csv(self) -> bool:
        """Load and parse CSV file."""
        print(f"Loading CSV: {self.csv_file}")
        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.headers = reader.fieldnames
                self.rows = list(reader)
            print(f"✓ {len(self.rows)} flows loaded")
            print(f"✓ {len(self.headers)} features found\n")
            return True
        except Exception as e:
            print(f"✗ Error loading file: {e}")
            return False

    def analyze(self) -> None:
        """Analyze all features and compute statistics."""
        print("Analyzing features...\n")

        for row in self.rows:
            for header in self.headers:
                value = row.get(header, '')
                stat = self.stats[header]

                if value == '' or value is None:
                    stat['empty_count'] += 1
                    continue

                try:
                    num_val = float(value)

                    if num_val == 0:
                        stat['zero_count'] += 1
                    else:
                        stat['non_zero_count'] += 1

                    stat['min'] = min(stat['min'], num_val)
                    stat['max'] = max(stat['max'], num_val)
                    stat['sum'] += num_val

                except ValueError:
                    stat['non_zero_count'] += 1

                if len(stat['unique_values']) < 100:
                    stat['unique_values'].add(value)

    def print_summary(self) -> None:
        """Print comprehensive feature analysis summary."""
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Flows: {len(self.rows)}")
        print(f"Total Features: {len(self.headers)}\n")

        always_zero: List[str] = []
        mostly_zero: List[Tuple[str, float]] = []
        good_features: List[Tuple[str, float]] = []
        always_empty: List[str] = []

        for header, stat in self.stats.items():
            total = len(self.rows)
            non_zero_pct = (stat['non_zero_count'] / total * 100) if total > 0 else 0

            if stat['empty_count'] == total:
                always_empty.append(header)
            elif stat['zero_count'] == total:
                always_zero.append(header)
            elif non_zero_pct < 10:
                mostly_zero.append((header, non_zero_pct))
            else:
                good_features.append((header, non_zero_pct))

        print(f"✓ Features with data: {len(good_features)} ({len(good_features) / len(self.headers) * 100:.1f}%)")
        print(f"⚠ Features always 0: {len(always_zero)} ({len(always_zero) / len(self.headers) * 100:.1f}%)")
        print(f"⚠ Features mostly 0 (<10%): {len(mostly_zero)} ({len(mostly_zero) / len(self.headers) * 100:.1f}%)")
        print(f"✗ Features always empty: {len(always_empty)} ({len(always_empty) / len(self.headers) * 100:.1f}%)")

        print("\n" + "=" * 80)
        print("PROBLEMATIC FEATURES")
        print("=" * 80)

        if always_empty:
            print(f"\n⚠ Always empty ({len(always_empty)}):")
            for feature in always_empty[:20]:
                print(f"  - {feature}")
            if len(always_empty) > 20:
                print(f"  ... and {len(always_empty) - 20} more")

        if always_zero:
            print(f"\n⚠ Always 0 ({len(always_zero)}):")
            for feature in always_zero[:20]:
                print(f"  - {feature}")
            if len(always_zero) > 20:
                print(f"  ... and {len(always_zero) - 20} more")

        if mostly_zero:
            print(f"\n⚠ Mostly 0 (<10% non-zero) ({len(mostly_zero)}):")
            mostly_zero.sort(key=lambda x: x[1])
            for feature, pct in mostly_zero[:20]:
                print(f"  - {feature}: {pct:.1f}% non-zero")
            if len(mostly_zero) > 20:
                print(f"  ... and {len(mostly_zero) - 20} more")

        print("\n" + "=" * 80)
        print("TOP FEATURES (most populated)")
        print("=" * 80)

        good_features.sort(key=lambda x: x[1], reverse=True)
        for feature, pct in good_features[:20]:
            stat = self.stats[feature]
            print(f"\n{feature}: {pct:.1f}% have values")
            print(f"  Unique values: {len(stat['unique_values'])}")
            if stat['min'] != float('inf'):
                print(f"  Range: {stat['min']:.2f} - {stat['max']:.2f}")
                if stat['non_zero_count'] > 0:
                    avg = stat['sum'] / stat['non_zero_count']
                    print(f"  Average: {avg:.2f}")

            if len(stat['unique_values']) <= 10:
                print(f"  Values: {', '.join(str(v) for v in list(stat['unique_values'])[:10])}")

    def check_basic_sanity(self) -> None:
        """Perform basic sanity checks on extracted features."""
        print("\n" + "=" * 80)
        print("SANITY CHECKS")
        print("=" * 80)

        issues: List[str] = []

        if len(self.rows) == 0:
            issues.append("✗ CRITICAL: No flows found!")
        else:
            print(f"✓ {len(self.rows)} flows present")

        critical_features = [
            'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',
            'L4_SRC_PORT', 'L4_DST_PORT',
            'PROTOCOL', 'IN_BYTES', 'OUT_BYTES'
        ]

        for feature in critical_features:
            if feature in self.stats:
                stat = self.stats[feature]
                non_zero_pct = (stat['non_zero_count'] / len(self.rows) * 100) if len(self.rows) > 0 else 0

                if stat['empty_count'] == len(self.rows):
                    issues.append(f"✗ CRITICAL: {feature} is always empty")
                elif non_zero_pct < 50:
                    issues.append(f"⚠ WARNING: {feature} has data in only {non_zero_pct:.1f}% of flows")
                else:
                    print(f"✓ {feature}: {non_zero_pct:.1f}% have data")

        if 'IPV4_SRC_ADDR' in self.stats:
            src_ips = self.stats['IPV4_SRC_ADDR']['unique_values']
            if src_ips and '0.0.0.0' not in src_ips:
                print(f"✓ IP addresses look valid ({len(src_ips)} unique)")
            elif not src_ips:
                issues.append("✗ CRITICAL: No IP addresses found")

        if 'PROTOCOL' in self.stats:
            protocols = self.stats['PROTOCOL']['unique_values']
            if protocols:
                print(f"✓ Protocols found: {', '.join(str(p) for p in protocols)}")
            else:
                issues.append("⚠ WARNING: No protocols detected")

        if 'IN_BYTES' in self.stats and 'OUT_BYTES' in self.stats:
            in_bytes_ok = self.stats['IN_BYTES']['non_zero_count'] > 0
            out_bytes_ok = self.stats['OUT_BYTES']['non_zero_count'] > 0

            if in_bytes_ok or out_bytes_ok:
                print(f"✓ Traffic data present")
            else:
                issues.append("✗ CRITICAL: No bytes counted (IN_BYTES and OUT_BYTES are 0)")

        if 'FLOW_START_MILLISECONDS' in self.stats:
            start_times = self.stats['FLOW_START_MILLISECONDS']
            if start_times['non_zero_count'] > 0:
                print(f"✓ Timestamps present")
            else:
                issues.append("⚠ WARNING: No timestamps found")

        print("\n" + "-" * 80)
        if not issues:
            print("✓✓✓ ALL CHECKS PASSED ✓✓✓")
            print("\nFeature extraction appears to have worked correctly!")
        else:
            print(f"⚠⚠⚠ {len(issues)} ISSUES FOUND ⚠⚠⚠\n")
            for issue in issues:
                print(issue)
            print("\nFeature extraction may NOT have worked correctly!")

    def export_summary(self, output_file: str = 'validation_report.txt') -> None:
        """Export validation report to file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"PCAP Feature Validation Report\n")
            f.write(f"CSV File: {self.csv_file}\n")
            f.write(f"Total Flows: {len(self.rows)}\n")
            f.write(f"Total Features: {len(self.headers)}\n\n")

            f.write("Features with data:\n")
            for header, stat in sorted(self.stats.items()):
                non_zero_pct = (stat['non_zero_count'] / len(self.rows) * 100) if len(self.rows) > 0 else 0
                f.write(f"  {header}: {non_zero_pct:.1f}% non-zero\n")

        print(f"\n✓ Report saved: {output_file}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python csv_validator.py <features.csv> [--export]")
        print("\nExamples:")
        print("  python csv_validator.py features.csv")
        print("  python csv_validator.py features.csv --export")
        sys.exit(1)

    csv_file = sys.argv[1]

    validator = CSVValidator(csv_file)

    if not validator.load_csv():
        sys.exit(1)

    validator.analyze()
    validator.print_summary()
    validator.check_basic_sanity()

    if '--export' in sys.argv:
        validator.export_summary()

    print("\n" + "=" * 80)
    print("Validation completed!")
    print("=" * 80)


if __name__ == '__main__':
    main()