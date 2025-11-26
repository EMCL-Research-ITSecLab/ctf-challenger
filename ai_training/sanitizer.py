#!/usr/bin/env python3
"""
Network traffic allowlister for PCAP files with temporal awareness.
Filters packets to keep only traffic from users who have given AI training consent.
Supports .pcap, .gz, and .zip formats with database-driven filtering.
"""

import gzip
import zipfile
import os
import sys
import glob
import tempfile
import struct
import socket
import time
import json
import ipaddress
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional, Any
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("Error: psycopg2 is required. Install with: pip install psycopg2-binary")
    sys.exit(1)


class IPAllowList:
    """Manages time-based IP allowlisting using database consent and trace data."""

    def __init__(self, db_host: str, db_user: str, db_pass: str, db_name: str = "ctf_challenger",
                 time_tolerance: float = 5.0):
        self.db_host = db_host
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.time_tolerance = time_tolerance
        self.conn = None
        self.allowance_rules: List[Dict[str, Any]] = []

        self.ip_ranges: List[Tuple[int, int, List[int]]] = []
        self.ip_cache: Dict[int, List[int]] = {}
        self.cache_max_size = 10000

        self.stats = {
            'exact_matches': 0,
            'tolerance_matches': 0,
            'total_checks': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def connect(self) -> None:
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(
                host=self.db_host,
                user=self.db_user,
                password=self.db_pass,
                database=self.db_name
            )
            print(f"✓ Connected to database at {self.db_host}")
        except Exception as e:
            print(f"Error connecting to database: {e}")
            sys.exit(1)

    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def load_allowance_rules(self) -> None:
        """Load IP allowance rules for users with AI training consent."""
        print("\n" + "=" * 80)
        print("LOADING ALLOWANCE RULES FROM DATABASE")
        print("=" * 80)
        print(f"Time tolerance: {self.time_tolerance} seconds")

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
                       SELECT username, email, vpn_static_ip
                       FROM users
                       WHERE ai_training_consent = TRUE
                       """)
        consenting_users = cursor.fetchall()

        print(f"Found {len(consenting_users)} users with AI training consent")

        for user in consenting_users:
            if user['vpn_static_ip']:
                try:
                    self.allowance_rules.append({
                        'username': user['username'],
                        'email': user['email'],
                        'network': ipaddress.ip_network(user['vpn_static_ip'] + '/32'),
                        'exact_start': 0.0,
                        'exact_stop': float('inf'),
                        'tolerance_start': 0.0,
                        'tolerance_stop': float('inf'),
                        'is_static_vpn': True
                    })
                    print(f"  Static VPN: {user['vpn_static_ip']} (always) ({user['username']})")
                except ValueError:
                    print(f"Warning: Invalid static VPN IP {user['vpn_static_ip']} for {user['username']}")

            self._load_user_networks(cursor, user['username'], user['email'])

        cursor.close()

        print(f"Total allowance rules: {len(self.allowance_rules)}")
        self.allowance_rules.sort(key=lambda x: x['exact_start'])
        self._build_ip_range_index()
        print(f"IP range index built: {len(self.ip_ranges)} ranges")

    def _load_user_networks(self, cursor, username: str, email: str) -> None:
        """Load user network traces through identity history."""
        usernames = {username}
        emails = {email}

        cursor.execute("""
                       SELECT username_new, email_new
                       FROM user_identification_history
                       WHERE username_old = %s
                          OR email_old = %s
                       ORDER BY changed_at
                       """, (username, email))

        for row in cursor.fetchall():
            if row['username_new']:
                usernames.add(row['username_new'])
            if row['email_new']:
                emails.add(row['email_new'])

        cursor.execute("""
                       SELECT username_old, email_old
                       FROM user_identification_history
                       WHERE username_new = %s
                          OR email_new = %s
                       ORDER BY changed_at DESC
                       """, (username, email))

        for row in cursor.fetchall():
            if row['username_old']:
                usernames.add(row['username_old'])
            if row['email_old']:
                emails.add(row['email_old'])

        cursor.execute("""
                       SELECT username, email, started_at, stopped_at, subnet
                       FROM user_network_trace
                       WHERE username = ANY (%s)
                          OR email = ANY (%s)
                       ORDER BY started_at
                       """, (list(usernames), list(emails)))

        traces = cursor.fetchall()

        for trace in traces:
            try:
                network = ipaddress.ip_network(trace['subnet'])
            except ValueError:
                print(f"Warning: Invalid subnet {trace['subnet']}")
                continue

            exact_start = trace['started_at'].timestamp()
            exact_stop = trace['stopped_at'].timestamp() if trace['stopped_at'] else float('inf')

            tolerance_start = exact_start - self.time_tolerance
            tolerance_stop = exact_stop + self.time_tolerance if exact_stop != float('inf') else float('inf')

            self.allowance_rules.append({
                'username': trace['username'],
                'email': trace['email'],
                'network': network,
                'exact_start': exact_start,
                'exact_stop': exact_stop,
                'tolerance_start': tolerance_start,
                'tolerance_stop': tolerance_stop,
                'is_static_vpn': False
            })

            if trace['stopped_at']:
                print(f"  Allow: {network} from {trace['started_at']} to {trace['stopped_at']} "
                      f"(±{self.time_tolerance}s) ({trace['username']})")
            else:
                print(f"  Allow: {network} from {trace['started_at']} (ongoing) "
                      f"(±{self.time_tolerance}s) ({trace['username']})")

    def _build_ip_range_index(self) -> None:
        """Build IP range index for binary search lookups."""
        range_to_indices = defaultdict(list)

        for idx, rule in enumerate(self.allowance_rules):
            network = rule['network']
            start_ip = int(network.network_address)
            end_ip = int(network.broadcast_address)
            range_key = (start_ip, end_ip)
            range_to_indices[range_key].append(idx)

        self.ip_ranges = [(start, end, indices) for (start, end), indices in range_to_indices.items()]
        self.ip_ranges.sort(key=lambda x: x[0])

    def _find_rule_indices_for_ip(self, ip_int: int) -> List[int]:
        """Find all rule indices that contain this IP."""
        if ip_int in self.ip_cache:
            self.stats['cache_hits'] += 1
            return self.ip_cache[ip_int]

        self.stats['cache_misses'] += 1
        result_indices = []

        for start_ip, end_ip, rule_indices in self.ip_ranges:
            if ip_int < start_ip:
                break
            if start_ip <= ip_int <= end_ip:
                result_indices.extend(rule_indices)

        if len(self.ip_cache) >= self.cache_max_size:
            keys_to_remove = list(self.ip_cache.keys())[:self.cache_max_size // 10]
            for key in keys_to_remove:
                del self.ip_cache[key]

        self.ip_cache[ip_int] = result_indices
        return result_indices

    def should_allow_packet(self, ip_str: str, packet_timestamp: float) -> Tuple[bool, bool]:
        """
        Check if IP should be allowed at given timestamp.

        Returns:
            (should_allow, used_tolerance)
        """
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip_str))[0]
        except (ValueError, OSError):
            return False, False

        self.stats['total_checks'] += 1

        candidate_indices = self._find_rule_indices_for_ip(ip_int)
        if not candidate_indices:
            return False, False

        for idx in candidate_indices:
            rule = self.allowance_rules[idx]
            if rule['exact_start'] <= packet_timestamp <= rule['exact_stop']:
                self.stats['exact_matches'] += 1
                return True, False

        if self.time_tolerance > 0:
            for idx in candidate_indices:
                rule = self.allowance_rules[idx]
                if rule['tolerance_start'] <= packet_timestamp <= rule['tolerance_stop']:
                    self.stats['tolerance_matches'] += 1
                    return True, True

        return False, False

    def print_stats(self) -> None:
        """Print statistics."""
        if self.stats['total_checks'] > 0:
            print("\n" + "=" * 80)
            print("ALLOWLIST STATISTICS")
            print("=" * 80)
            print(f"Total IP checks:            {self.stats['total_checks']:,}")
            print(f"Exact matches:              {self.stats['exact_matches']:,}")
            print(f"Tolerance matches:          {self.stats['tolerance_matches']:,}")
            if self.stats['tolerance_matches'] > 0:
                pct = (self.stats['tolerance_matches'] / (
                        self.stats['exact_matches'] + self.stats['tolerance_matches'])) * 100
                print(f"Tolerance usage rate:       {pct:.2f}%")

            total_lookups = self.stats['cache_hits'] + self.stats['cache_misses']
            if total_lookups > 0:
                cache_rate = (self.stats['cache_hits'] / total_lookups) * 100
                print(f"\nCache performance:")
                print(f"  Cache hits:               {self.stats['cache_hits']:,}")
                print(f"  Cache misses:             {self.stats['cache_misses']:,}")
                print(f"  Cache hit rate:           {cache_rate:.2f}%")


def decompress_file(filepath: str) -> Tuple[str, Optional[str]]:
    """Decompress .gz or .zip file to temporary location."""
    if filepath.endswith('.gz'):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            temp_file = tmp.name
        print(f"  Decompressing .gz file...")
        with gzip.open(filepath, 'rb') as f_in:
            with open(temp_file, 'wb') as f_out:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
        print(f"  ✓ Decompressed")
        return temp_file, temp_file

    elif filepath.endswith('.zip'):
        print(f"  Extracting .zip file...")
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            pcap_files = [name for name in zip_ref.namelist() if name.endswith('.pcap')]
            if not pcap_files:
                raise ValueError(f"No .pcap file found in zip: {filepath}")
            if len(pcap_files) > 1:
                print(f"  Warning: Multiple .pcap files, using: {pcap_files[0]}")

            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                temp_file = tmp.name

            with zip_ref.open(pcap_files[0]) as source:
                with open(temp_file, 'wb') as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
        print(f"  ✓ Extracted: {pcap_files[0]}")
        return temp_file, temp_file

    return filepath, None


class PCAPAllowLister:
    """Filters PCAP files to keep only allowed packets."""

    def __init__(self, allowlist: IPAllowList):
        self.allowlist = allowlist
        self.stats = {
            'total_packets_read': 0,
            'packets_allowed': 0,
            'packets_allowed_exact': 0,
            'packets_allowed_tolerance': 0,
            'packets_removed': 0,
            'processing_start': time.time()
        }

    def filter_pcap(self, input_path: str, output_path: str,
                    dry_run: bool = False) -> Dict[str, Any]:
        """Process PCAP file, keeping only allowed packets."""
        print("\n" + "=" * 80)
        print(f"FILTERING: {input_path}")
        print("=" * 80)

        if dry_run:
            print("DRY RUN MODE - No output will be written")

        result = {
            'input': input_path,
            'output': output_path if not dry_run else None,
            'packets_read': 0,
            'packets_allowed': 0,
            'packets_allowed_exact': 0,
            'packets_allowed_tolerance': 0,
            'packets_removed': 0
        }

        file_stats = {
            'packets_read': 0,
            'packets_allowed': 0,
            'packets_allowed_exact': 0,
            'packets_allowed_tolerance': 0,
            'packets_removed': 0
        }

        try:
            decompressed_input, temp_input = decompress_file(input_path)

            temp_output = None
            if not dry_run:
                if output_path.endswith('.gz') or output_path.endswith('.zip'):
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                        temp_output = tmp.name
                    actual_output = temp_output
                else:
                    actual_output = output_path

            with open(decompressed_input, 'rb', buffering=1024 * 1024) as f_in:
                magic_bytes = f_in.read(4)
                if len(magic_bytes) < 4:
                    print(f"Invalid PCAP format")
                    return result

                magic = struct.unpack('I', magic_bytes)[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP magic: {hex(magic)}")
                    return result

                f_in.seek(0)
                global_header = f_in.read(24)

                if not dry_run:
                    f_out = open(actual_output, 'wb', buffering=1024 * 1024)
                    f_out.write(global_header)

                while True:
                    packet_header = f_in.read(16)
                    if len(packet_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        endian + 'IIII', packet_header
                    )

                    packet_data = f_in.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    file_stats['packets_read'] += 1
                    packet_timestamp = ts_sec + ts_usec / 1000000.0

                    should_allow, used_tolerance = self._should_allow_packet(
                        packet_data, packet_timestamp
                    )

                    if should_allow:
                        file_stats['packets_allowed'] += 1
                        if used_tolerance:
                            file_stats['packets_allowed_tolerance'] += 1
                        else:
                            file_stats['packets_allowed_exact'] += 1

                        if not dry_run:
                            f_out.write(packet_header)
                            f_out.write(packet_data)
                    else:
                        file_stats['packets_removed'] += 1

                    if file_stats['packets_read'] % 50000 == 0:
                        print(f"  Processed {file_stats['packets_read']:,} packets, "
                              f"allowed {file_stats['packets_allowed']:,}, "
                              f"removed {file_stats['packets_removed']:,}", end='\r')

                if not dry_run:
                    f_out.close()

                print(f"  Processed {file_stats['packets_read']:,} packets, "
                      f"allowed {file_stats['packets_allowed']:,} "
                      f"(exact: {file_stats['packets_allowed_exact']:,}, "
                      f"tolerance: {file_stats['packets_allowed_tolerance']:,}), "
                      f"removed {file_stats['packets_removed']:,}")

            result.update(file_stats)
            self.stats['total_packets_read'] += file_stats['packets_read']
            self.stats['packets_allowed'] += file_stats['packets_allowed']
            self.stats['packets_allowed_exact'] += file_stats['packets_allowed_exact']
            self.stats['packets_allowed_tolerance'] += file_stats['packets_allowed_tolerance']
            self.stats['packets_removed'] += file_stats['packets_removed']

            if not dry_run:
                if output_path.endswith('.gz'):
                    print(f"\n  Compressing to {output_path}...")
                    with open(temp_output, 'rb') as f_in:
                        with gzip.open(output_path, 'wb', compresslevel=6) as f_out:
                            while True:
                                chunk = f_in.read(8 * 1024 * 1024)
                                if not chunk:
                                    break
                                f_out.write(chunk)
                    print(f"  ✓ Compressed")
                    os.remove(temp_output)

                elif output_path.endswith('.zip'):
                    print(f"\n  Compressing to {output_path}...")
                    base_name = os.path.basename(output_path).replace('.zip', '.pcap')
                    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
                        zip_out.write(temp_output, arcname=base_name)
                    print(f"  ✓ Compressed")
                    os.remove(temp_output)

            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

        return result

    def _should_allow_packet(self, data: bytes, packet_timestamp: float) -> Tuple[bool, bool]:
        """
        Check if packet should be allowed based on IP allowlist.
        Both source and destination IPs must pass temporal check.

        Returns:
            (should_allow, used_tolerance)
        """
        try:
            if len(data) < 14:
                return False, False

            eth_type = (data[12] << 8) | data[13]
            if eth_type != 0x0800:
                return False, False

            ip_data = data[14:]
            if len(ip_data) < 20:
                return False, False

            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            src_allow, src_tol = self.allowlist.should_allow_packet(
                src_ip, packet_timestamp
            )
            dst_allow, dst_tol = self.allowlist.should_allow_packet(
                dst_ip, packet_timestamp
            )

            if src_allow and dst_allow:
                return True, (src_tol or dst_tol)

            return False, False

        except Exception:
            return False, False

    def print_stats(self) -> None:
        """Print statistics."""
        total_time = time.time() - self.stats['processing_start']
        print("\n" + "=" * 80)
        print("FILTERING STATISTICS")
        print("=" * 80)
        print(f"Total processing time:       {total_time:.2f}s")
        print(f"Allowance rules:             {len(self.allowlist.allowance_rules)}")
        print(f"Time tolerance:              {self.allowlist.time_tolerance}s")
        print(f"\nPackets allowed (exact):     {self.stats['packets_allowed_exact']:,}")
        print(f"Packets allowed (tolerance): {self.stats['packets_allowed_tolerance']:,}")
        if self.stats['packets_allowed_tolerance'] > 0:
            total = self.stats['packets_allowed_exact'] + self.stats['packets_allowed_tolerance']
            pct = (self.stats['packets_allowed_tolerance'] / total) * 100
            print(f"Tolerance usage rate:        {pct:.2f}%")
        print("=" * 80)


def merge_pcaps(output_path: str, input_paths: List[str], force: bool = False) -> None:
    """Merge multiple PCAP files into a single file."""
    print("\n" + "=" * 80)
    print("MERGING PCAP FILES")
    print("=" * 80)

    if os.path.exists(output_path) and not force:
        response = input(f"Output file '{output_path}' exists. Overwrite? [y/N]: ")
        if response.strip().lower() not in ('y', 'yes'):
            print("Merge aborted")
            return

    is_compressed_gz = output_path.endswith('.gz')
    is_compressed_zip = output_path.endswith('.zip')

    if is_compressed_gz or is_compressed_zip:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            temp_output = tmp.name
        actual_output = temp_output
    else:
        actual_output = output_path

    with open(actual_output, 'wb', buffering=1024 * 1024) as f_out:
        first = True
        for input_path in input_paths:
            print(f"Merging: {input_path}")
            decompressed_path, temp_file = decompress_file(input_path)

            with open(decompressed_path, 'rb') as f_in:
                if first:
                    f_out.write(f_in.read(24))
                    first = False
                else:
                    f_in.read(24)

                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)

            if temp_file and os.path.exists(temp_file):
                os.remove(temp_file)

    if is_compressed_gz:
        print(f"Compressing to .gz...")
        with open(temp_output, 'rb') as f_in:
            with gzip.open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
        os.remove(temp_output)
    elif is_compressed_zip:
        print(f"Compressing to .zip...")
        base_name = os.path.basename(output_path).replace('.zip', '.pcap')
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_out:
            zip_out.write(temp_output, arcname=base_name)
        os.remove(temp_output)

    print(f"✓ Merged {len(input_paths)} files into {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_allowlister.py <pcap_file(s)> [options]")
        print("\nPCAP Allowlister - Filters packets to keep only traffic from users with AI training consent")
        print("\nSupported formats: .pcap, .pcap.gz, .zip")
        print("\nDatabase Options (required):")
        print("  --db-host <host>          Database host (default: 10.0.0.102)")
        print("  --db-user <user>          Database username (required)")
        print("  --db-pass <pass>          Database password (required)")
        print("  --db-name <name>          Database name (default: ctf_challenger)")
        print("  --time-tolerance <sec>    Time tolerance in seconds (default: 5.0)")
        print("\nOutput Options:")
        print("  --out-dir <dir>           Output directory (default: current)")
        print("  --suffix <suffix>         Output filename suffix (default: _allowed)")
        print("  --merge-output <file>     Merge all outputs into single file")
        print("\nMode Options:")
        print("  --dry-run                 Show what would be done without writing")
        print("  --force                   Overwrite existing files without prompting")
        print("  --report <file>           Write JSON report")
        print("\nExamples:")
        print("  python pcap_allowlister.py traffic.pcap --db-user admin --db-pass secret")
        print("  python pcap_allowlister.py *.pcap.gz --db-user admin --db-pass secret --time-tolerance 10")
        sys.exit(1)

    input_files = []
    db_host = "10.0.0.102"
    db_user = None
    db_pass = None
    db_name = "ctf_challenger"
    time_tolerance = 5.0
    out_dir = '.'
    suffix = '_allowed'
    merge_output = None
    dry_run = False
    force = False
    report_file = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--db-host' and i + 1 < len(sys.argv):
            db_host = sys.argv[i + 1]
            i += 2
        elif arg == '--db-user' and i + 1 < len(sys.argv):
            db_user = sys.argv[i + 1]
            i += 2
        elif arg == '--db-pass' and i + 1 < len(sys.argv):
            db_pass = sys.argv[i + 1]
            i += 2
        elif arg == '--db-name' and i + 1 < len(sys.argv):
            db_name = sys.argv[i + 1]
            i += 2
        elif arg == '--time-tolerance' and i + 1 < len(sys.argv):
            time_tolerance = float(sys.argv[i + 1])
            i += 2
        elif arg == '--out-dir' and i + 1 < len(sys.argv):
            out_dir = sys.argv[i + 1]
            i += 2
        elif arg == '--suffix' and i + 1 < len(sys.argv):
            suffix = sys.argv[i + 1]
            i += 2
        elif arg == '--merge-output' and i + 1 < len(sys.argv):
            merge_output = sys.argv[i + 1]
            i += 2
        elif arg == '--dry-run':
            dry_run = True
            i += 1
        elif arg == '--force':
            force = True
            i += 1
        elif arg == '--report' and i + 1 < len(sys.argv):
            report_file = sys.argv[i + 1]
            i += 2
        else:
            input_files.append(arg)
            i += 1

    all_files = []
    for pattern in input_files:
        all_files.extend(glob.glob(pattern))

    if not all_files:
        print("Error: No input files found")
        sys.exit(1)

    if not (db_user and db_pass):
        print("Error: --db-user and --db-pass are required")
        sys.exit(1)

    allowlist = IPAllowList(
        db_host=db_host,
        db_user=db_user,
        db_pass=db_pass,
        db_name=db_name,
        time_tolerance=time_tolerance
    )
    allowlist.connect()
    allowlist.load_allowance_rules()

    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    for inp in all_files:
        base = os.path.basename(inp)
        if base.endswith('.pcap.gz'):
            name = base[:-8]
            ext = '.pcap.gz'
        elif base.endswith('.zip'):
            name = base[:-4]
            ext = '.zip'
        else:
            name = os.path.splitext(base)[0]
            ext = '.pcap.gz'

        out_name = name + suffix + ext
        out_path = os.path.join(out_dir, out_name)
        outputs.append((inp, out_path))

    if not force and not dry_run:
        existing = [o for (_, o) in outputs if os.path.exists(o)]
        if existing:
            print("The following files exist:")
            for e in existing:
                print(f"  {e}")
            response = input("Overwrite? [y/N]: ")
            if response.strip().lower() not in ('y', 'yes'):
                print("Aborted")
                allowlist.close()
                sys.exit(0)

    print("=" * 80)
    print("PCAP ALLOWLISTER")
    print("=" * 80)
    print(f"Configuration:")
    print(f"  DB host:          {db_host}")
    print(f"  DB name:          {db_name}")
    print(f"  Time tolerance:   {time_tolerance}s")
    print(f"  Input files:      {len(all_files)}")
    print(f"  Output directory: {out_dir}")
    if merge_output:
        print(f"  Merge output:     {merge_output}")
    if dry_run:
        print(f"  DRY RUN MODE")
    print("=" * 80)

    start_time = time.time()
    results = []

    lister = PCAPAllowLister(allowlist=allowlist)

    for inp, outp in outputs:
        result = lister.filter_pcap(inp, outp, dry_run=dry_run)
        results.append(result)

    lister.print_stats()
    allowlist.print_stats()

    if merge_output and not dry_run:
        allowed_files = [o for (_, o) in outputs]
        merge_pcaps(merge_output, allowed_files, force)

    total_time = time.time() - start_time

    if report_file:
        report = {
            'time_tolerance': time_tolerance,
            'total_time': total_time,
            'files': results
        }
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n✓ Report written to {report_file}")

    allowlist.close()

    print("\n" + "=" * 80)
    print("COMPLETED!")
    print("=" * 80)
    print(f"Total time: {total_time:.2f}s")
    print(f"Files processed: {len(results)}")


if __name__ == '__main__':
    main()