#!/usr/bin/env python3
"""
Network traffic sanitizer for PCAP files with temporal awareness.
Removes traffic based on user consent and temporal IP assignments.
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
import re
from collections import deque, defaultdict
from typing import Dict, Set, List, Tuple, Optional, Any
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("Error: psycopg2 is required. Install with: pip install psycopg2-binary")
    sys.exit(1)


class TemporalIPFilter:
    """Manages time-based IP filtering using database consent and trace data."""

    def __init__(self, db_host: str, db_user: str, db_pass: str, db_name: str = "ctf_challenger"):
        self.db_host = db_host
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.conn = None
        self.temporal_removals: List[Dict[str, Any]] = []

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

    def load_removal_rules(self) -> None:
        """Load IP removal rules based on user consent and temporal assignments."""
        print("\n" + "=" * 80)
        print("LOADING REMOVAL RULES FROM DATABASE")
        print("=" * 80)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
                       SELECT username, email, vpn_static_ip
                       FROM users
                       WHERE ai_training_consent = FALSE
                       """)
        non_consenting_users = cursor.fetchall()

        print(f"Found {len(non_consenting_users)} users without AI training consent")

        for user in non_consenting_users:
            self._trace_user_networks(cursor, user['username'], user['email'])

        cursor.close()

        print(f"Total temporal removal rules: {len(self.temporal_removals)}")

        self.temporal_removals.sort(key=lambda x: x['started_at'])

    def _trace_user_networks(self, cursor, username: str, email: str) -> None:
        """Trace user through identity history and collect all network assignments."""

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

        username_list = list(usernames)
        email_list = list(emails)

        cursor.execute("""
                       SELECT username, email, started_at, stopped_at, subnet
                       FROM user_network_trace
                       WHERE username = ANY (%s)
                          OR email = ANY (%s)
                       ORDER BY started_at
                       """, (username_list, email_list))

        traces = cursor.fetchall()

        for trace in traces:
            try:
                network = ipaddress.ip_network(trace['subnet'])
            except ValueError:
                print(f"Warning: Invalid subnet {trace['subnet']}")
                continue

            started_at = trace['started_at'].timestamp()
            stopped_at = trace['stopped_at'].timestamp() if trace['stopped_at'] else float('inf')

            self.temporal_removals.append({
                'username': trace['username'],
                'email': trace['email'],
                'network': network,
                'started_at': started_at,
                'stopped_at': stopped_at
            })

            if trace['stopped_at']:
                print(f"  Rule: {network} from {trace['started_at']} to {trace['stopped_at']} "
                      f"({trace['username']})")
            else:
                print(f"  Rule: {network} from {trace['started_at']} (ongoing) "
                      f"({trace['username']})")

    def should_remove_packet(self, ip_str: str, packet_timestamp: float) -> bool:
        """Check if IP should be removed at given timestamp."""
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for rule in self.temporal_removals:
            if rule['started_at'] <= packet_timestamp <= rule['stopped_at']:
                if ip_addr in rule['network']:
                    return True

        return False


class PCAPSanitizer:
    def __init__(self, temporal_filter: Optional[TemporalIPFilter] = None,
                 seed_ips: Optional[Set[str]] = None, max_depth: int = -1,
                 allowed_networks: Optional[List[str]] = None):
        self.temporal_filter = temporal_filter
        self.seed_ips = seed_ips or set()
        self.max_depth = max_depth
        self.allowed_networks = self._parse_networks(allowed_networks or ['10.128.0.0/9'])
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.removal_set: Set[str] = set()
        self.stats = {
            'total_packets_read': 0,
            'packets_removed': 0,
            'packets_kept': 0,
            'flows_analyzed': 0,
            'endpoints_removed': 0,
            'processing_start': time.time()
        }

    def _parse_networks(self, network_strs: List[str]) -> List[Any]:
        """Parse CIDR notation networks."""
        networks = []
        for net_str in network_strs:
            try:
                networks.append(ipaddress.ip_network(net_str.strip()))
            except ValueError as e:
                print(f"Warning: Invalid network {net_str}: {e}")
        return networks

    def _ip_in_allowed(self, ip_str: str) -> bool:
        """Check if IP is within allowed networks."""
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for network in self.allowed_networks:
            if ip_addr.version == network.version and ip_addr in network:
                return True
        return False

    def build_communication_graph(self, pcap_files: List[str]) -> None:
        """First pass: Build communication graph from PCAP files."""
        print("\n" + "=" * 80)
        print("BUILDING COMMUNICATION GRAPH")
        print("=" * 80)

        for filepath in pcap_files:
            print(f"Analyzing: {filepath}")
            self._analyze_pcap(filepath)

        print(f"Total flows analyzed: {self.stats['flows_analyzed']:,}")
        print(f"Unique endpoints: {len(self.adjacency):,}")

    def _analyze_pcap(self, filepath: str) -> None:
        """Analyze a single PCAP file to build adjacency graph."""
        try:
            temp_file = None

            if filepath.endswith('.gz'):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                    temp_file = tmp.name
                with gzip.open(filepath, 'rb') as f_in:
                    with open(temp_file, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(1024 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                filepath = temp_file

            with open(filepath, 'rb', buffering=1024 * 1024) as f:
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    print(f"Invalid PCAP format (header too short): {filepath}")
                    return
                magic = struct.unpack('I', magic_bytes)[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP magic: {hex(magic)} for {filepath}")
                    return

                f.read(20)

                packet_count = 0
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        endian + 'IIII', packet_header
                    )

                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    self._extract_endpoints(packet_data)
                    packet_count += 1

                    if packet_count % 50000 == 0:
                        print(f"  Analyzed {packet_count:,} packets, "
                              f"{len(self.adjacency):,} endpoints", end='\r')

                print(f"  Analyzed {packet_count:,} packets, "
                      f"{len(self.adjacency):,} endpoints")

            if temp_file and os.path.exists(temp_file):
                os.remove(temp_file)

        except Exception as e:
            print(f"Error analyzing {filepath}: {e}")

    def _extract_endpoints(self, data: bytes) -> None:
        """Extract source and destination IPs from packet."""
        try:
            if len(data) < 14:
                return

            eth_type = (data[12] << 8) | data[13]

            if eth_type != 0x0800:  # Only IPv4
                return

            ip_data = data[14:]
            if len(ip_data) < 20:
                return

            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            self.adjacency[src_ip].add(dst_ip)
            self.adjacency[dst_ip].add(src_ip)
            self.stats['flows_analyzed'] += 1

        except Exception:
            pass

    def compute_removal_set(self) -> None:
        """Compute set of IPs to remove using BFS from seed IPs."""
        if not self.seed_ips:
            print("\nSkipping graph-based removal (no seed IPs provided)")
            return

        print("\n" + "=" * 80)
        print("COMPUTING REMOVAL SET")
        print("=" * 80)
        print(f"Seed IPs: {len(self.seed_ips)}")
        print(f"Max depth: {'unlimited' if self.max_depth < 0 else self.max_depth}")

        queue = deque()
        visited: Set[str] = set()
        depth: Dict[str, int] = {}

        for seed in self.seed_ips:
            if self._ip_in_allowed(seed):
                if seed not in visited:
                    visited.add(seed)
                    depth[seed] = 0
                    queue.append(seed)
            else:
                for neighbor in self.adjacency.get(seed, set()):
                    if self._ip_in_allowed(neighbor) and neighbor not in visited:
                        visited.add(neighbor)
                        depth[neighbor] = 0
                        queue.append(neighbor)

        while queue:
            node = queue.popleft()
            current_depth = depth[node]

            if 0 <= self.max_depth <= current_depth:
                continue

            for neighbor in self.adjacency.get(node, set()):
                if not self._ip_in_allowed(neighbor):
                    continue

                if neighbor not in visited:
                    visited.add(neighbor)
                    depth[neighbor] = current_depth + 1
                    queue.append(neighbor)

        self.removal_set = visited
        self.stats['endpoints_removed'] = len(self.removal_set)

        print(f"Endpoints to remove: {len(self.removal_set):,}")
        if len(self.removal_set) <= 20:
            for ip in sorted(self.removal_set):
                print(f"  - {ip}")

    def sanitize_pcap(self, input_path: str, output_path: str,
                      dry_run: bool = False, base_timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Second pass: Write sanitized PCAP file with temporal filtering."""
        print("\n" + "=" * 80)
        print(f"SANITIZING: {input_path}")
        print("=" * 80)

        if base_timestamp:
            print(f"Base timestamp: {datetime.fromtimestamp(base_timestamp)}")

        if dry_run:
            print("DRY RUN MODE - No output will be written")

        result = {
            'input': input_path,
            'output': output_path if not dry_run else None,
            'packets_read': 0,
            'packets_removed': 0,
            'packets_kept': 0,
            'base_timestamp': base_timestamp
        }

        try:
            temp_input = None
            temp_output = None

            if input_path.endswith('.gz'):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                    temp_input = tmp.name
                with gzip.open(input_path, 'rb') as f_in:
                    with open(temp_input, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(1024 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                input_path = temp_input

            if not dry_run:
                if output_path.endswith('.gz'):
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                        temp_output = tmp.name
                    actual_output = temp_output
                else:
                    actual_output = output_path

            with open(input_path, 'rb', buffering=1024 * 1024) as f_in:
                magic_bytes = f_in.read(4)
                if len(magic_bytes) < 4:
                    print(f"Invalid PCAP format (header too short): {input_path}")
                    return result
                magic = struct.unpack('I', magic_bytes)[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP format")
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

                    result['packets_read'] += 1

                    packet_timestamp = ts_sec + ts_usec / 1000000.0
                    if base_timestamp:
                        absolute_timestamp = base_timestamp + packet_timestamp
                    else:
                        absolute_timestamp = packet_timestamp

                    if self._should_remove_packet(packet_data, absolute_timestamp):
                        result['packets_removed'] += 1
                    else:
                        result['packets_kept'] += 1
                        if not dry_run:
                            f_out.write(packet_header)
                            f_out.write(packet_data)

                    if result['packets_read'] % 50000 == 0:
                        print(f"  Processed {result['packets_read']:,} packets, "
                              f"removed {result['packets_removed']:,}, "
                              f"kept {result['packets_kept']:,}", end='\r')

                if not dry_run:
                    f_out.close()

                print(f"  Processed {result['packets_read']:,} packets, "
                      f"removed {result['packets_removed']:,}, "
                      f"kept {result['packets_kept']:,}")

            if not dry_run and output_path.endswith('.gz'):
                with open(temp_output, 'rb') as f_in:
                    with gzip.open(output_path, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(1024 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                os.remove(temp_output)

            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)

        except Exception as e:
            print(f"Error sanitizing {input_path}: {e}")
            import traceback
            traceback.print_exc()

        return result

    def _should_remove_packet(self, data: bytes, packet_timestamp: float) -> bool:
        """Check if packet should be removed based on static and temporal rules."""
        try:
            if len(data) < 14:
                return False

            eth_type = (data[12] << 8) | data[13]

            if eth_type != 0x0800:  # Only IPv4
                return False

            ip_data = data[14:]
            if len(ip_data) < 20:
                return False

            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            if src_ip in self.removal_set or dst_ip in self.removal_set:
                return True

            if self.temporal_filter:
                if (self.temporal_filter.should_remove_packet(src_ip, packet_timestamp) or
                        self.temporal_filter.should_remove_packet(dst_ip, packet_timestamp)):
                    return True

            return False

        except Exception:
            return False

    def print_stats(self) -> None:
        """Print final statistics."""
        total_time = time.time() - self.stats['processing_start']
        print("\n" + "=" * 80)
        print("SANITIZATION STATISTICS")
        print("=" * 80)
        print(f"Total processing time:      {total_time:.2f}s")
        if self.seed_ips:
            print(f"Seed IPs:                   {len(self.seed_ips)}")
            print(f"Endpoints removed (graph):  {self.stats['endpoints_removed']:,}")
        if self.temporal_filter:
            print(f"Temporal rules:             {len(self.temporal_filter.temporal_removals)}")
        print(f"Allowed networks:           {len(self.allowed_networks)}")
        for net in self.allowed_networks:
            print(f"  - {net}")
        print("=" * 80)


def extract_timestamp_from_filename(filename: str, cli_timestamp: Optional[float] = None) -> Optional[float]:
    """Extract base timestamp from filename pattern *.pcap.[timestamp]-* or use CLI override."""
    if cli_timestamp is not None:
        return cli_timestamp

    # Pattern: *.pcap.1761107064-2025-10-23-1761230876.gz
    # Extract first number after .pcap.
    basename = os.path.basename(filename)
    match = re.search(r'\.pcap\.(\d+)', basename)
    if match:
        return float(match.group(1))

    return None


def load_seed_ips(ips_str: Optional[str] = None,
                  ips_file: Optional[str] = None) -> Set[str]:
    """Load seed IPs from string or file."""
    seeds = set()

    if ips_str:
        for ip in ips_str.split(','):
            ip = ip.strip()
            if ip:
                seeds.add(ip)

    if ips_file:
        if not os.path.exists(ips_file):
            print(f"Error: IPs file not found: {ips_file}")
            sys.exit(1)
        with open(ips_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    seeds.add(line)

    return seeds


def merge_pcaps(output_path: str, input_paths: List[str],
                force: bool = False) -> None:
    """Merge multiple PCAP files into one."""
    print("\n" + "=" * 80)
    print("MERGING PCAP FILES")
    print("=" * 80)

    if os.path.exists(output_path) and not force:
        response = input(f"Output file '{output_path}' exists. Overwrite? [y/N]: ")
        if response.strip().lower() not in ('y', 'yes'):
            print("Merge aborted")
            return

    is_compressed = output_path.endswith('.gz')

    if is_compressed:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            temp_output = tmp.name
        actual_output = temp_output
    else:
        actual_output = output_path

    with open(actual_output, 'wb', buffering=1024 * 1024) as f_out:
        first = True

        for input_path in input_paths:
            print(f"Merging: {input_path}")

            temp_input = None
            if input_path.endswith('.gz'):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                    temp_input = tmp.name
                with gzip.open(input_path, 'rb') as f_in:
                    with open(temp_input, 'wb') as f_tmp:
                        while True:
                            chunk = f_in.read(1024 * 1024)
                            if not chunk:
                                break
                            f_tmp.write(chunk)
                input_path = temp_input

            with open(input_path, 'rb') as f_in:
                if first:
                    global_header = f_in.read(24)
                    f_out.write(global_header)
                    first = False
                else:
                    f_in.read(24)
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)

            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)

    if is_compressed:
        with open(temp_output, 'rb') as f_in:
            with gzip.open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
        os.remove(temp_output)

    print(f"✓ Merged {len(input_paths)} files into {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_sanitizer.py <pcap_file(s)> [options]")
        print("\nDatabase Options (for temporal filtering):")
        print("  --db-host <host>          Database host (default: 10.0.0.102)")
        print("  --db-user <user>          Database username (required for DB mode)")
        print("  --db-pass <pass>          Database password (required for DB mode)")
        print("  --db-name <name>          Database name (default: ctf_challenger)")
        print("\nStatic Filtering Options:")
        print("  --ips <ip,ip,...>         Comma-separated seed IPs for graph-based removal")
        print("  --ips-file <file>         File with one IP per line")
        print("  --max-depth <n>           Max spider depth, -1=unlimited (default: -1)")
        print("  --allowed-network <cidr>  CIDR to constrain spidering (default: 10.128.0.0/9)")
        print("\nTimestamp Options:")
        print("  --base-timestamp <unix>   Override base timestamp (default: extract from filename)")
        print("\nOutput Options:")
        print("  --out-dir <dir>           Output directory (default: current dir)")
        print("  --suffix <suffix>         Output filename suffix (default: _cleaned)")
        print("  --merge-output <file>     Merge all outputs into single file")
        print("\nMode Options:")
        print("  --per-file                Build separate graph per file")
        print("  --dry-run                 Don't write output, show what would be removed")
        print("  --force                   Overwrite existing files without prompting")
        print("  --report <file>           Write JSON report")
        print("\nExamples:")
        print("  # Database-driven temporal filtering")
        print("  python pcap_sanitizer.py --db-user admin --db-pass secret traffic.pcap")
        print("")
        print("  # Static IP filtering with graph spidering")
        print("  python pcap_sanitizer.py --ips 192.168.1.100 traffic.pcap")
        print("")
        print("  # Combined: database temporal + static graph-based")
        print("  python pcap_sanitizer.py --db-user admin --db-pass secret \\")
        print("                           --ips 10.0.0.1 --max-depth 2 *.pcap.gz")
        print("")
        print("  # Override base timestamp")
        print("  python pcap_sanitizer.py --db-user admin --db-pass secret \\")
        print("                           --base-timestamp 1761107064 traffic.pcap")
        sys.exit(1)

    input_files = []
    db_host = "10.0.0.102"
    db_user = None
    db_pass = None
    db_name = "ctf_challenger"
    ips_str = None
    ips_file = None
    out_dir = '.'
    suffix = '_cleaned'
    max_depth = -1
    allowed_network = '10.128.0.0/9'
    per_file = False
    merge_output = None
    dry_run = False
    force = False
    report_file = None
    cli_base_timestamp = None

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
        elif arg == '--ips' and i + 1 < len(sys.argv):
            ips_str = sys.argv[i + 1]
            i += 2
        elif arg == '--ips-file' and i + 1 < len(sys.argv):
            ips_file = sys.argv[i + 1]
            i += 2
        elif arg == '--out-dir' and i + 1 < len(sys.argv):
            out_dir = sys.argv[i + 1]
            i += 2
        elif arg == '--suffix' and i + 1 < len(sys.argv):
            suffix = sys.argv[i + 1]
            i += 2
        elif arg == '--max-depth' and i + 1 < len(sys.argv):
            max_depth = int(sys.argv[i + 1])
            i += 2
        elif arg == '--allowed-network' and i + 1 < len(sys.argv):
            allowed_network = sys.argv[i + 1]
            i += 2
        elif arg == '--per-file':
            per_file = True
            i += 1
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
        elif arg == '--base-timestamp' and i + 1 < len(sys.argv):
            try:
                cli_base_timestamp = float(sys.argv[i + 1])
            except ValueError:
                print("Error: --base-timestamp must be a number (unix epoch)")
                sys.exit(1)
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

    seed_ips = load_seed_ips(ips_str, ips_file)

    if not seed_ips and not (db_user and db_pass):
        print("Error: Must provide --ips/--ips-file or database credentials (--db-user and --db-pass)")
        sys.exit(1)

    temporal_filter = None
    if db_user and db_pass:
        temporal_filter = TemporalIPFilter(db_host=db_host, db_user=db_user, db_pass=db_pass, db_name=db_name)
        temporal_filter.connect()
        temporal_filter.load_removal_rules()
    else:
        temporal_filter = None

    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    for inp in all_files:
        base = os.path.basename(inp)
        # Preserve multi-extensions properly (.pcap.gz)
        name = base
        if base.endswith('.pcap.gz'):
            name = base[:-8]
            ext = '.pcap.gz'
        else:
            name = os.path.splitext(base)[0]
            ext = '.pcap.gz' if base.endswith('.gz') else '.pcap'
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
                if temporal_filter:
                    temporal_filter.close()
                sys.exit(0)

    print("=" * 80)
    print("PCAP SANITIZER")
    print("=" * 80)
    print(f"Configuration:")
    print(f"  Seed IPs:         {len(seed_ips)}")
    print(f"  Max depth:        {'unlimited' if max_depth < 0 else max_depth}")
    print(f"  Allowed network:  {allowed_network}")
    print(f"  Per-file mode:    {per_file}")
    print(f"  Input files:      {len(all_files)}")
    print(f"  Output directory: {out_dir}")
    if merge_output:
        print(f"  Merge output:     {merge_output}")
    if dry_run:
        print(f"  DRY RUN MODE")
    if temporal_filter:
        print(f"  DB host:          {db_host}")
        print(f"  DB name:          {db_name}")
    print("=" * 80)

    start_time = time.time()
    results = []

    allowed_networks_list = [allowed_network]

    if per_file:
        for inp, outp in outputs:
            sanitizer = PCAPSanitizer(temporal_filter=temporal_filter,
                                      seed_ips=seed_ips,
                                      max_depth=max_depth,
                                      allowed_networks=allowed_networks_list)

            if seed_ips:
                sanitizer.build_communication_graph([inp])
                sanitizer.compute_removal_set()
            else:
                print(f"Skipping graph build for {inp} (DB-only mode)")

            base_ts = extract_timestamp_from_filename(inp, cli_base_timestamp)
            result = sanitizer.sanitize_pcap(inp, outp, dry_run=dry_run, base_timestamp=base_ts)
            results.append(result)
            sanitizer.print_stats()
    else:
        sanitizer = PCAPSanitizer(temporal_filter=temporal_filter,
                                  seed_ips=seed_ips,
                                  max_depth=max_depth,
                                  allowed_networks=allowed_networks_list)
        if seed_ips:
            sanitizer.build_communication_graph(all_files)
            sanitizer.compute_removal_set()
        else:
            print("Skipping graph build (DB-only mode). Using temporal rules only.")

        for inp, outp in outputs:
            base_ts = extract_timestamp_from_filename(inp, cli_base_timestamp)
            result = sanitizer.sanitize_pcap(inp, outp, dry_run=dry_run, base_timestamp=base_ts)
            results.append(result)

        sanitizer.print_stats()

    if merge_output and not dry_run:
        cleaned_files = [o for (_, o) in outputs]
        merge_pcaps(merge_output, cleaned_files, force)

    total_time = time.time() - start_time

    report = {
        'seed_ips': sorted(seed_ips),
        'allowed_network': allowed_network,
        'max_depth': max_depth,
        'per_file': per_file,
        'total_time': total_time,
        'files': results
    }

    if report_file:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n✓ Report written to {report_file}")

    if temporal_filter:
        temporal_filter.close()

    print("\n" + "=" * 80)
    print("COMPLETED!")
    print("=" * 80)
    print(f"Total time: {total_time:.2f}s")
    print(f"Files processed: {len(results)}")


if __name__ == '__main__':
    main()