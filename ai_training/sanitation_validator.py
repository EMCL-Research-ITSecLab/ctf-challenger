#!/usr/bin/env python3
"""
PCAP Sanitization Verifier
Verifies that packets were correctly removed based on temporal and static rules.
Supports .pcap, .gz, and .zip formats.
"""

import struct
import socket
import ipaddress
import sys
import re
import os
import gzip
import zipfile
import tempfile
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("Error: psycopg2 is required. Install with: pip install psycopg2-binary")
    sys.exit(1)


def decompress_file(filepath: str) -> Tuple[str, Optional[str]]:
    """
    Decompress a .gz or .zip file to a temporary location.
    Returns (decompressed_path, temp_file_to_cleanup)
    """
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
                raise ValueError(f"No .pcap file found in zip archive: {filepath}")
            if len(pcap_files) > 1:
                print(f"  Warning: Multiple .pcap files in archive, using first: {pcap_files[0]}")

            pcap_name = pcap_files[0]
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                temp_file = tmp.name

            with zip_ref.open(pcap_name) as source:
                with open(temp_file, 'wb') as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
        print(f"  ✓ Extracted: {pcap_name}")
        return temp_file, temp_file

    else:
        # No decompression needed
        return filepath, None


class TemporalRuleLoader:
    """Loads temporal removal rules from database."""

    def __init__(self, db_host: str, db_user: str, db_pass: str, db_name: str = "ctf_challenger"):
        self.db_host = db_host
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.conn = None
        self.temporal_rules: List[Dict] = []

    def connect(self) -> None:
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
        if self.conn:
            self.conn.close()

    def load_rules(self) -> None:
        """Load temporal removal rules from database."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
                       SELECT username, email, vpn_static_ip
                       FROM users
                       WHERE ai_training_consent = FALSE
                       """)
        non_consenting_users = cursor.fetchall()

        print(f"Found {len(non_consenting_users)} users without consent")

        for user in non_consenting_users:
            if user['vpn_static_ip']:
                try:
                    self.temporal_rules.append({
                        'username': user['username'],
                        'email': user['email'],
                        'network': ipaddress.ip_network(user['vpn_static_ip'] + '/32'),  # /32 = single IP
                        'started_at': 0.0,
                        'stopped_at': float('inf'),  # Forever
                        'is_static_vpn': True
                    })
                    print(f"  Static VPN IP: {user['vpn_static_ip']} (always) ({user['username']})")
                except ValueError:
                    print(f"Warning: Invalid static VPN IP {user['vpn_static_ip']} for {user['username']}")

            self._trace_user_networks(cursor, user['username'], user['email'])

        cursor.close()
        print(f"Loaded {len(self.temporal_rules)} temporal rules")

    def _trace_user_networks(self, cursor, username: str, email: str) -> None:
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
                started_at = trace['started_at'].timestamp()
                stopped_at = trace['stopped_at'].timestamp() if trace['stopped_at'] else float('inf')

                self.temporal_rules.append({
                    'username': trace['username'],
                    'email': trace['email'],
                    'network': network,
                    'started_at': started_at,
                    'stopped_at': stopped_at
                })
            except ValueError:
                print(f"Warning: Invalid subnet {trace['subnet']}")

    def should_be_removed(self, ip_str: str, timestamp: float) -> Tuple[bool, Optional[str]]:
        """Check if IP should be removed at timestamp. Returns (should_remove, reason)."""
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, None

        for rule in self.temporal_rules:
            if rule['started_at'] <= timestamp <= rule['stopped_at']:
                if ip_addr in rule['network']:
                    reason = f"{rule['username']} @ {rule['network']} ({datetime.fromtimestamp(rule['started_at'])} - {datetime.fromtimestamp(rule['stopped_at']) if rule['stopped_at'] != float('inf') else 'ongoing'})"
                    return True, reason

        return False, None


class PCAPVerifier:
    """Verifies PCAP sanitization."""

    def __init__(self, temporal_loader: Optional[TemporalRuleLoader] = None,
                 static_ips: Optional[Set[str]] = None,
                 allowed_networks: Optional[List[str]] = None):
        self.temporal_loader = temporal_loader
        self.static_ips = static_ips or set()
        self.allowed_networks = self._parse_networks(allowed_networks or ['10.128.0.0/9'])

        self.stats = {
            'total_packets': 0,
            'violations_found': 0,
            'violations_temporal': 0,
            'violations_static': 0,
            'packets_ok': 0
        }
        self.violations: List[Dict] = []

    def _parse_networks(self, network_strs: List[str]) -> List:
        networks = []
        for net_str in network_strs:
            try:
                networks.append(ipaddress.ip_network(net_str.strip()))
            except ValueError as e:
                print(f"Warning: Invalid network {net_str}: {e}")
        return networks

    def _ip_in_allowed(self, ip_str: str) -> bool:
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for network in self.allowed_networks:
            if ip_addr.version == network.version and ip_addr in network:
                return True
        return False

    def verify_pcap(self, filepath: str, base_timestamp: Optional[float] = None) -> Dict:
        """Verify a single PCAP file."""
        print("\n" + "=" * 80)
        print(f"VERIFYING: {filepath}")
        print("=" * 80)

        if base_timestamp:
            print(f"Base timestamp: {datetime.fromtimestamp(base_timestamp)}")

        result = {
            'file': filepath,
            'base_timestamp': base_timestamp,
            'packets_checked': 0,
            'violations': [],
            'status': 'PASS'
        }

        try:
            decompressed_path, temp_file = decompress_file(filepath)

            with open(decompressed_path, 'rb', buffering=1024 * 1024) as f:
                magic_bytes = f.read(4)
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

                f.read(20)  # Skip rest of global header

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

                    result['packets_checked'] += 1
                    self.stats['total_packets'] += 1

                    packet_timestamp = ts_sec + ts_usec / 1000000.0
                    if base_timestamp:
                        absolute_timestamp = base_timestamp + packet_timestamp
                    else:
                        absolute_timestamp = packet_timestamp

                    violation = self._check_packet(packet_data, absolute_timestamp, result['packets_checked'])
                    if violation:
                        result['violations'].append(violation)
                        self.violations.append({**violation, 'file': filepath})
                        self.stats['violations_found'] += 1
                        if violation['type'] == 'temporal':
                            self.stats['violations_temporal'] += 1
                        elif violation['type'] == 'static':
                            self.stats['violations_static'] += 1
                    else:
                        self.stats['packets_ok'] += 1

                    if result['packets_checked'] % 50000 == 0:
                        print(f"  Checked {result['packets_checked']:,} packets, "
                              f"found {len(result['violations'])} violations", end='\r')

            if temp_file and os.path.exists(temp_file):
                os.remove(temp_file)

            print(f"  Checked {result['packets_checked']:,} packets, "
                  f"found {len(result['violations'])} violations")

            if result['violations']:
                result['status'] = 'FAIL'
                print(f"\n❌ VERIFICATION FAILED: {len(result['violations'])} violations found")
            else:
                print(f"\n✓ VERIFICATION PASSED: No violations found")

        except Exception as e:
            print(f"Error verifying {filepath}: {e}")
            import traceback
            traceback.print_exc()

        return result

    def _check_packet(self, data: bytes, timestamp: float, packet_num: int) -> Optional[Dict]:
        """Check if packet violates removal rules."""
        try:
            if len(data) < 14:
                return None

            eth_type = (data[12] << 8) | data[13]
            if eth_type != 0x0800:  # IPv4
                return None

            ip_data = data[14:]
            if len(ip_data) < 20:
                return None

            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            if src_ip in self.static_ips or dst_ip in self.static_ips:
                return {
                    'packet_num': packet_num,
                    'timestamp': timestamp,
                    'datetime': datetime.fromtimestamp(timestamp).isoformat(),
                    'type': 'static',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'reason': f"Static IP in removal set: {src_ip if src_ip in self.static_ips else dst_ip}"
                }

            if self.temporal_loader:
                should_remove_src, reason_src = self.temporal_loader.should_be_removed(src_ip, timestamp)
                should_remove_dst, reason_dst = self.temporal_loader.should_be_removed(dst_ip, timestamp)

                if should_remove_src or should_remove_dst:
                    return {
                        'packet_num': packet_num,
                        'timestamp': timestamp,
                        'datetime': datetime.fromtimestamp(timestamp).isoformat(),
                        'type': 'temporal',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'reason': reason_src if should_remove_src else reason_dst
                    }

            return None

        except Exception:
            return None

    def print_summary(self) -> None:
        """Print verification summary."""
        print("\n" + "=" * 80)
        print("VERIFICATION SUMMARY")
        print("=" * 80)
        print(f"Total packets checked:      {self.stats['total_packets']:,}")
        print(f"Packets OK:                 {self.stats['packets_ok']:,}")
        print(f"Violations found:           {self.stats['violations_found']:,}")
        print(f"  - Temporal violations:    {self.stats['violations_temporal']:,}")
        print(f"  - Static violations:      {self.stats['violations_static']:,}")

        if self.stats['violations_found'] > 0:
            print(f"\n❌ OVERALL STATUS: FAIL")
            print("\nFirst 10 violations:")
            for i, v in enumerate(self.violations[:10]):
                print(f"\n  Violation #{i + 1}:")
                print(f"    File:      {v['file']}")
                print(f"    Packet:    #{v['packet_num']}")
                print(f"    Time:      {v['datetime']}")
                print(f"    Type:      {v['type']}")
                print(f"    Flow:      {v['src_ip']} -> {v['dst_ip']}")
                print(f"    Reason:    {v['reason']}")
        else:
            print(f"\n✓ OVERALL STATUS: PASS")
            print("All packets comply with removal rules!")

        print("=" * 80)


def extract_timestamp_from_filename(filename: str) -> Optional[float]:
    """Extract base timestamp from filename."""
    basename = os.path.basename(filename)
    match = re.search(r'\.pcap\.(\d+)', basename)
    if match:
        return float(match.group(1))
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_verifier.py <pcap_file(s)> [options]")
        print("\nSupported formats: .pcap, .pcap.gz, .zip")
        print("\nDatabase Options:")
        print("  --db-host <host>          Database host (default: 10.0.0.102)")
        print("  --db-user <user>          Database username")
        print("  --db-pass <pass>          Database password")
        print("  --db-name <name>          Database name (default: ctf_challenger)")
        print("\nStatic IP Options:")
        print("  --static-ips <ip,ip,...>  Comma-separated IPs that should be removed")
        print("  --static-ips-file <file>  File with one IP per line")
        print("\nTimestamp Options:")
        print("  --base-timestamp <unix>   Override base timestamp")
        print("\nOther Options:")
        print("  --allowed-network <cidr>  CIDR network scope (default: 10.128.0.0/9)")
        print("\nExamples:")
        print("  # Verify temporal filtering")
        print("  python pcap_verifier.py --db-user admin --db-pass secret cleaned.pcap")
        print("")
        print("  # Verify .zip files")
        print("  python pcap_verifier.py --db-user admin --db-pass secret cleaned.zip")
        print("")
        print("  # Verify static IP removal")
        print("  python pcap_verifier.py --static-ips 192.168.1.100 cleaned.pcap")
        print("")
        print("  # Verify both")
        print("  python pcap_verifier.py --db-user admin --db-pass secret \\")
        print("                          --static-ips 10.0.0.1 cleaned*.pcap.gz")
        sys.exit(1)

    input_files = []
    db_host = "10.0.0.102"
    db_user = None
    db_pass = None
    db_name = "ctf_challenger"
    static_ips_str = None
    static_ips_file = None
    allowed_network = '10.128.0.0/9'
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
        elif arg == '--static-ips' and i + 1 < len(sys.argv):
            static_ips_str = sys.argv[i + 1]
            i += 2
        elif arg == '--static-ips-file' and i + 1 < len(sys.argv):
            static_ips_file = sys.argv[i + 1]
            i += 2
        elif arg == '--allowed-network' and i + 1 < len(sys.argv):
            allowed_network = sys.argv[i + 1]
            i += 2
        elif arg == '--base-timestamp' and i + 1 < len(sys.argv):
            try:
                cli_base_timestamp = float(sys.argv[i + 1])
            except ValueError:
                print("Error: --base-timestamp must be a number")
                sys.exit(1)
            i += 2
        else:
            input_files.append(arg)
            i += 1

    if not input_files:
        print("Error: No input files specified")
        sys.exit(1)

    static_ips = set()
    if static_ips_str:
        for ip in static_ips_str.split(','):
            ip = ip.strip()
            if ip:
                static_ips.add(ip)

    if static_ips_file:
        if not os.path.exists(static_ips_file):
            print(f"Error: File not found: {static_ips_file}")
            sys.exit(1)
        with open(static_ips_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    static_ips.add(line)

    temporal_loader = None
    if db_user and db_pass:
        temporal_loader = TemporalRuleLoader(db_host, db_user, db_pass, db_name)
        temporal_loader.connect()
        temporal_loader.load_rules()

    if not static_ips and not temporal_loader:
        print("Error: Must provide either --static-ips/--static-ips-file or database credentials")
        sys.exit(1)

    print("=" * 80)
    print("PCAP SANITIZATION VERIFIER")
    print("=" * 80)
    print(f"Configuration:")
    print(f"  Static IPs:       {len(static_ips)}")
    print(f"  Temporal rules:   {len(temporal_loader.temporal_rules) if temporal_loader else 0}")
    print(f"  Allowed network:  {allowed_network}")
    print(f"  Input files:      {len(input_files)}")
    print("=" * 80)

    verifier = PCAPVerifier(
        temporal_loader=temporal_loader,
        static_ips=static_ips,
        allowed_networks=[allowed_network]
    )

    results = []
    for filepath in input_files:
        base_ts = cli_base_timestamp or extract_timestamp_from_filename(filepath)
        result = verifier.verify_pcap(filepath, base_ts)
        results.append(result)

    verifier.print_summary()

    if temporal_loader:
        temporal_loader.close()

    sys.exit(1 if verifier.stats['violations_found'] > 0 else 0)


if __name__ == '__main__':
    main()