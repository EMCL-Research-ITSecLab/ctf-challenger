#!/usr/bin/env python3
"""
Network traffic PCAP splitter.
Splits PCAP files by challenge template based on IP-to-challenge mappings from database.
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
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("Error: psycopg2 is required. Install with: pip install psycopg2-binary")
    sys.exit(1)


class PacketClassifier:
    """Packet classification with skip reason tracking."""

    SKIP_REASONS = {
        'eth_too_short': 'Ethernet frame too short',
        'not_ipv4': 'Not IPv4 protocol',
        'ip_header_too_short': 'IP header too short',
        'invalid_ip': 'Invalid IP address',
        'ip_not_allowed': 'IP not in allowed networks',
        'no_time_overlap': 'No time overlap with challenge',
        'no_challenge_mapping': 'No challenge mapping for IP/time',
        'non_tcp_udp': 'Non-TCP/UDP protocol (ICMP, etc)',
        'fragmented': 'Fragmented IP packet',
        'multicast_broadcast': 'Multicast or broadcast address',
        'private_ip': 'Private IP (non-challenge)',
        'loopback': 'Loopback address',
        'link_local': 'Link-local address',
    }


class ChallengeMapper:
    """Maps IP addresses and timestamps to challenge templates."""

    def __init__(self, db_host: str, db_user: str, db_pass: str, db_name: str = "ctf_challenger",
                 time_tolerance: float = 5.0, prefer_closest: bool = True):
        self.db_host = db_host
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.time_tolerance = time_tolerance
        self.prefer_closest = prefer_closest
        self.conn = None

        self.challenge_mappings: List[Dict[str, Any]] = []
        self.template_names: Dict[int, str] = {}
        self.ip_ranges: List[Tuple[int, int, List[int]]] = []
        self.ip_cache: Dict[int, List[int]] = {}
        self.cache_max_size = 10000

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

    def load_challenge_mappings(self) -> None:
        """Load challenge-to-network mappings from database."""
        print("\n" + "=" * 80)
        print("LOADING CHALLENGE MAPPINGS FROM DATABASE")
        print("=" * 80)
        print(f"Time tolerance: {self.time_tolerance} seconds")
        print(f"Match strategy: {'CLOSEST MATCH' if self.prefer_closest else 'FIRST MATCH'}")

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        try:
            cursor.execute("SELECT id, name FROM challenge_templates ORDER BY id")
            templates = cursor.fetchall()
            for template in templates:
                template_id = template['id']
                name = template.get('name') or f"template_{template_id}"
                self.template_names[template_id] = name
            print(f"Found {len(self.template_names)} challenge templates")
        except Exception as e:
            print(f"Warning: Could not load template names: {e}")

        cursor.execute("""
                       SELECT cc.id,
                              cc.user_id,
                              cc.challenge_template_id,
                              cc.started_at,
                              cc.completed_at,
                              u.username,
                              u.email
                       FROM completed_challenges cc
                                JOIN users u ON cc.user_id = u.id
                       ORDER BY cc.started_at
                       """)

        challenges = cursor.fetchall()
        print(f"Found {len(challenges)} completed challenges")

        challenge_count = 0
        mapping_count = 0

        for challenge in challenges:
            user_id = challenge['user_id']
            username = challenge['username']
            email = challenge['email']
            template_id = challenge['challenge_template_id']
            started_at = challenge['started_at']
            completed_at = challenge['completed_at']

            cursor.execute("""
                           SELECT subnet, started_at, stopped_at
                           FROM user_network_trace
                           WHERE (username = %s OR email = %s)
                             AND started_at <= %s
                             AND (stopped_at >= %s OR stopped_at IS NULL)
                           ORDER BY started_at
                           """, (username, email, completed_at, started_at))

            traces = cursor.fetchall()

            if traces:
                challenge_count += 1
                for trace in traces:
                    try:
                        network = ipaddress.ip_network(trace['subnet'])
                    except ValueError:
                        print(f"Warning: Invalid subnet {trace['subnet']}")
                        continue

                    trace_start = trace['started_at'].timestamp()
                    trace_stop = trace['stopped_at'].timestamp() if trace['stopped_at'] else float('inf')

                    exact_start = trace_start
                    exact_stop = trace_stop

                    tolerance_start = exact_start - self.time_tolerance
                    tolerance_stop = exact_stop + self.time_tolerance if exact_stop != float('inf') else float('inf')

                    self.challenge_mappings.append({
                        'challenge_id': challenge['id'],
                        'user_id': user_id,
                        'username': username,
                        'email': email,
                        'template_id': template_id,
                        'network': network,
                        'exact_start': exact_start,
                        'exact_stop': exact_stop,
                        'tolerance_start': tolerance_start,
                        'tolerance_stop': tolerance_stop,
                        'subnet': trace['subnet'],
                    })
                    mapping_count += 1

        cursor.close()
        self._build_ip_range_index()

        print(f"\nTotal mappings created: {mapping_count} from {challenge_count} challenges")
        print(f"Unique templates: {len(set(m['template_id'] for m in self.challenge_mappings))}")
        print(f"IP range index built: {len(self.ip_ranges)} ranges")

    def _build_ip_range_index(self) -> None:
        """Build IP range index for binary search lookups."""
        range_to_indices = defaultdict(list)

        for idx, mapping in enumerate(self.challenge_mappings):
            network = mapping['network']
            start_ip = int(network.network_address)
            end_ip = int(network.broadcast_address)
            range_key = (start_ip, end_ip)
            range_to_indices[range_key].append(idx)

        self.ip_ranges = [(start, end, indices) for (start, end), indices in range_to_indices.items()]
        self.ip_ranges.sort(key=lambda x: x[0])

    def _find_mapping_indices_for_ip(self, ip_int: int) -> List[int]:
        """Find all mapping indices that contain this IP using binary search."""
        if ip_int in self.ip_cache:
            return self.ip_cache[ip_int]

        result_indices = []

        for start_ip, end_ip, mapping_indices in self.ip_ranges:
            if ip_int < start_ip:
                break
            if start_ip <= ip_int <= end_ip:
                result_indices.extend(mapping_indices)

        if len(self.ip_cache) >= self.cache_max_size:
            keys_to_remove = list(self.ip_cache.keys())[:self.cache_max_size // 10]
            for key in keys_to_remove:
                del self.ip_cache[key]

        self.ip_cache[ip_int] = result_indices
        return result_indices

    def _calculate_time_distance(self, packet_ts: float, mapping: Dict) -> Tuple[float, bool]:
        """
        Calculate minimum time distance from packet timestamp to mapping's time window.
        Returns: (distance_in_seconds, used_tolerance_flag)
        """
        if mapping['exact_start'] <= packet_ts <= mapping['exact_stop']:
            return 0.0, False

        if packet_ts < mapping['exact_start']:
            exact_dist = mapping['exact_start'] - packet_ts
        else:
            exact_dist = packet_ts - mapping['exact_stop']

        if self.time_tolerance > 0:
            if mapping['tolerance_start'] <= packet_ts <= mapping['tolerance_stop']:
                return exact_dist, True

        if packet_ts < mapping['tolerance_start']:
            return mapping['tolerance_start'] - packet_ts, False
        else:
            return packet_ts - mapping['tolerance_stop'], False

    def get_challenge_template_fast(self, ip_int: int, packet_timestamp: float,
                                    collect_debug: bool = False) -> Tuple[
        Optional[int], Optional[str], Optional[Dict], bool]:
        """
        Map IP and timestamp to challenge template.

        Args:
            ip_int: IP address as integer
            packet_timestamp: Packet timestamp in seconds
            collect_debug: Whether to collect debug information

        Returns:
            (template_id, skip_reason, debug_info, used_tolerance)
        """
        cache_key = ip_int
        if cache_key in self.ip_cache:
            candidate_indices = self.ip_cache[cache_key]
        else:
            candidate_indices = []
            for start_ip, end_ip, mapping_indices in self.ip_ranges:
                if ip_int < start_ip:
                    break
                if start_ip <= ip_int <= end_ip:
                    candidate_indices.extend(mapping_indices)

            if len(self.ip_cache) >= self.cache_max_size:
                keys_to_remove = list(self.ip_cache.keys())[:self.cache_max_size // 10]
                for key in keys_to_remove:
                    del self.ip_cache[key]
            self.ip_cache[cache_key] = candidate_indices

        if not candidate_indices:
            return None, 'ip_not_allowed', None, False

        if self.prefer_closest:
            best_match = None
            best_distance = float('inf')
            best_used_tolerance = False

            for idx in candidate_indices:
                mapping = self.challenge_mappings[idx]
                distance, used_tol = self._calculate_time_distance(packet_timestamp, mapping)

                if distance < best_distance or (distance == best_distance and not used_tol):
                    best_distance = distance
                    best_match = mapping
                    best_used_tolerance = used_tol

            if best_distance == 0.0 or (best_used_tolerance and best_distance <= self.time_tolerance):
                return best_match['template_id'], None, None, best_used_tolerance

            min_distance = best_distance
        else:
            for idx in candidate_indices:
                mapping = self.challenge_mappings[idx]
                if mapping['exact_start'] <= packet_timestamp <= mapping['exact_stop']:
                    return mapping['template_id'], None, None, False

            if self.time_tolerance > 0:
                for idx in candidate_indices:
                    mapping = self.challenge_mappings[idx]
                    if mapping['tolerance_start'] <= packet_timestamp <= mapping['tolerance_stop']:
                        return mapping['template_id'], None, None, True

            min_distance = float('inf')
            for idx in candidate_indices:
                mapping = self.challenge_mappings[idx]
                dist, _ = self._calculate_time_distance(packet_timestamp, mapping)
                min_distance = min(min_distance, dist)

        if not collect_debug:
            return None, 'no_challenge_mapping', None, False

        ip_str = socket.inet_ntoa(struct.pack('!I', ip_int))

        debug_info = {
            'ip': ip_str,
            'packet_timestamp': packet_timestamp,
            'packet_time_str': datetime.fromtimestamp(packet_timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'min_time_distance': min_distance,
            'potential_matches': [],
            'total_mappings_checked': len(candidate_indices)
        }

        for idx in candidate_indices:
            mapping = self.challenge_mappings[idx]
            dist, _ = self._calculate_time_distance(packet_timestamp, mapping)

            debug_info['potential_matches'].append({
                'template_id': mapping['template_id'],
                'template_name': self.template_names.get(mapping['template_id'], f"template_{mapping['template_id']}"),
                'username': mapping['username'],
                'network': str(mapping['network']),
                'exact_window': f"{datetime.fromtimestamp(mapping['exact_start']).strftime('%Y-%m-%d %H:%M:%S')} - {datetime.fromtimestamp(mapping['exact_stop']).strftime('%Y-%m-%d %H:%M:%S')}",
                'time_distance': dist,
            })

        return None, 'no_challenge_mapping', debug_info, False


def decompress_file(filepath: str) -> Tuple[str, Optional[str]]:
    """Decompress .gz or .zip file to temporary location."""
    if filepath.endswith('.gz'):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            temp_file = tmp.name
        print(f"  Decompressing .gz file...")
        with gzip.open(filepath, 'rb') as f_in:
            with open(temp_file, 'wb') as f_out:
                while True:
                    chunk = f_in.read(4 * 1024 * 1024)
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

            pcap_name = pcap_files[0]
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                temp_file = tmp.name

            with zip_ref.open(pcap_name) as source:
                with open(temp_file, 'wb') as target:
                    while True:
                        chunk = source.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
        print(f"  ✓ Extracted")
        return temp_file, temp_file

    else:
        return filepath, None


class PCAPSplitter:
    """Splits PCAP files by challenge template."""

    BROADCAST_IP = int(ipaddress.IPv4Address('255.255.255.255'))

    def __init__(self, challenge_mapper: ChallengeMapper, output_dir: str,
                 compress: bool = True, allowed_networks: Optional[List[str]] = None,
                 log_unmapped: bool = False):
        self.challenge_mapper = challenge_mapper
        self.output_dir = output_dir
        self.compress = compress
        self.allowed_networks = self._parse_networks(allowed_networks or ['10.128.0.0/9'])
        self.log_unmapped = log_unmapped

        self.allowed_ranges = []
        for net in self.allowed_networks:
            start = int(net.network_address)
            end = int(net.broadcast_address)
            self.allowed_ranges.append((start, end))

        self.output_files: Dict[int, Any] = {}
        self.temp_files: Dict[int, str] = {}

        self.stats = {
            'total_packets_read': 0,
            'packets_written': 0,
            'packets_written_exact': 0,
            'packets_written_tolerance': 0,
            'packets_skipped': 0,
            'packets_per_template': defaultdict(int),
            'skip_reasons': Counter(),
            'ip_protocols': Counter(),
            'unmapped_packets': [],
            'processing_start': time.time(),
            'min_distances': [],
            'packet_time_range': [float('inf'), float('-inf')],
            'extreme_misses': [],
        }
        self.global_header = None

        self.last_progress_time = time.time()
        self.progress_interval = 0.5

    def _parse_networks(self, network_strs: List[str]) -> List[Any]:
        """Parse CIDR notation networks."""
        networks = []
        for net_str in network_strs:
            try:
                networks.append(ipaddress.ip_network(net_str.strip()))
            except ValueError as e:
                print(f"Warning: Invalid network {net_str}: {e}")
        return networks

    def _ip_int_in_allowed(self, ip_int: int) -> bool:
        """Check if IP integer is in allowed ranges."""
        for start, end in self.allowed_ranges:
            if start <= ip_int <= end:
                return True
        return False

    def _get_output_file(self, template_id: int, endian: str) -> Any:
        """Get or create output file handle for template."""
        if template_id not in self.output_files:
            template_name = self.challenge_mapper.template_names.get(
                template_id, f"template_{template_id}"
            )
            safe_name = re.sub(r'[^\w\-_]', '_', template_name)

            if self.compress:
                temp_fd = tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix='.pcap',
                    dir=self.output_dir,
                    prefix=f"{safe_name}_"
                )
                temp_path = temp_fd.name
                temp_fd.close()

                self.temp_files[template_id] = temp_path
                f = open(temp_path, 'wb', buffering=8 * 1024 * 1024)
            else:
                output_path = os.path.join(self.output_dir, f"{safe_name}.pcap")
                f = open(output_path, 'wb', buffering=8 * 1024 * 1024)

            if self.global_header:
                f.write(self.global_header)

            self.output_files[template_id] = f
            print(f"  Created output for template {template_id}: {safe_name}")

        return self.output_files[template_id]

    def split_pcap(self, input_path: str, base_timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Split PCAP file by challenge template."""
        print("\n" + "=" * 80)
        print(f"SPLITTING: {input_path}")
        print("=" * 80)

        result = {
            'input': input_path,
            'packets_read': 0,
            'packets_written': 0,
            'packets_written_exact': 0,
            'packets_written_tolerance': 0,
            'packets_skipped': 0,
            'skip_reasons': Counter(),
        }

        try:
            decompressed_input, temp_input = decompress_file(input_path)

            with open(decompressed_input, 'rb', buffering=8 * 1024 * 1024) as f_in:
                magic_bytes = f_in.read(4)
                if len(magic_bytes) < 4:
                    print(f"Invalid PCAP format: {input_path}")
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
                self.global_header = f_in.read(24)

                header_fmt = endian + 'IIII'
                header_size = 16

                last_progress = 0
                progress_interval = 50000

                while True:
                    packet_header = f_in.read(header_size)
                    if len(packet_header) < header_size:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(header_fmt, packet_header)

                    packet_data = f_in.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    result['packets_read'] += 1
                    self.stats['total_packets_read'] += 1

                    packet_timestamp = ts_sec + ts_usec / 1000000.0

                    self.stats['packet_time_range'][0] = min(self.stats['packet_time_range'][0], packet_timestamp)
                    self.stats['packet_time_range'][1] = max(self.stats['packet_time_range'][1], packet_timestamp)

                    template_id, skip_reason, debug_info, used_tolerance = self._classify_packet(
                        packet_data, packet_timestamp
                    )

                    if template_id is not None:
                        output_file = self._get_output_file(template_id, endian)
                        output_file.write(packet_header)
                        output_file.write(packet_data)

                        result['packets_written'] += 1
                        self.stats['packets_written'] += 1
                        self.stats['packets_per_template'][template_id] += 1

                        if used_tolerance:
                            result['packets_written_tolerance'] += 1
                            self.stats['packets_written_tolerance'] += 1
                        else:
                            result['packets_written_exact'] += 1
                            self.stats['packets_written_exact'] += 1
                    else:
                        result['packets_skipped'] += 1
                        self.stats['packets_skipped'] += 1
                        result['skip_reasons'][skip_reason] += 1
                        self.stats['skip_reasons'][skip_reason] += 1

                        if skip_reason == 'no_challenge_mapping' and debug_info:
                            if self.log_unmapped:
                                self.stats['unmapped_packets'].append(debug_info)
                            if 'min_time_distance' in debug_info:
                                dist = debug_info['min_time_distance']
                                self.stats['min_distances'].append(dist)
                                if dist > 3600:
                                    self.stats['extreme_misses'].append({
                                        'distance': dist,
                                        'ip': debug_info.get('ip'),
                                        'timestamp': packet_timestamp,
                                        'time_str': debug_info.get('packet_time_str'),
                                        'matches': len(debug_info.get('potential_matches', []))
                                    })

                    if result['packets_read'] - last_progress >= progress_interval:
                        current_time = time.time()
                        if current_time - self.last_progress_time >= self.progress_interval:
                            elapsed = current_time - self.stats['processing_start']
                            rate = self.stats['total_packets_read'] / elapsed if elapsed > 0 else 0
                            print(f"  {result['packets_read']:,} pkts | "
                                  f"written: {result['packets_written']:,} | "
                                  f"rate: {rate:,.0f} pkt/s", end='\r')
                            self.last_progress_time = current_time
                            last_progress = result['packets_read']

                print(f"  Processed {result['packets_read']:,} packets, "
                      f"written {result['packets_written']:,}, "
                      f"skipped {result['packets_skipped']:,}    ")

            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)

        except Exception as e:
            print(f"Error splitting {input_path}: {e}")
            import traceback
            traceback.print_exc()

        return result

    def _classify_packet(self, data: bytes, packet_timestamp: float) -> Tuple[
        Optional[int], Optional[str], Optional[Dict], bool]:
        """
        Classify packet and map to challenge template.

        Returns:
            (template_id, skip_reason, debug_info, used_tolerance)
        """
        try:
            if len(data) < 34:
                return None, 'eth_too_short', None, False

            eth_type = (data[12] << 8) | data[13]
            if eth_type != 0x0800:
                return None, 'not_ipv4', None, False

            ip_data = data[14:]
            if len(ip_data) < 20:
                return None, 'ip_header_too_short', None, False

            ip_protocol = ip_data[9]
            self.stats['ip_protocols'][ip_protocol] += 1

            src_ip_int = struct.unpack('!I', ip_data[12:16])[0]
            dst_ip_int = struct.unpack('!I', ip_data[16:20])[0]

            if src_ip_int == self.BROADCAST_IP or dst_ip_int == self.BROADCAST_IP:
                return None, 'multicast_broadcast', None, False

            frag_offset = struct.unpack('>H', ip_data[6:8])[0]
            if (frag_offset & 0x1FFF) != 0 or (frag_offset & 0x2000) != 0:
                return None, 'fragmented', None, False

            src_allowed = self._ip_int_in_allowed(src_ip_int)
            dst_allowed = self._ip_int_in_allowed(dst_ip_int)

            if not (src_allowed or dst_allowed):
                return None, 'ip_not_allowed', None, False

            collect_debug = self.log_unmapped

            if src_allowed:
                template_id, reason, debug, used_tol = self.challenge_mapper.get_challenge_template_fast(
                    src_ip_int, packet_timestamp, collect_debug=collect_debug
                )
                if template_id is not None:
                    return template_id, None, None, used_tol
                debug_info = debug if collect_debug else None
            else:
                debug_info = None

            if dst_allowed:
                template_id, reason, debug, used_tol = self.challenge_mapper.get_challenge_template_fast(
                    dst_ip_int, packet_timestamp, collect_debug=collect_debug
                )
                if template_id is not None:
                    return template_id, None, None, used_tol
                if collect_debug and (not src_allowed or debug_info is None):
                    debug_info = debug

            if collect_debug and debug_info and 'min_time_distance' in debug_info:
                self.stats['min_distances'].append(debug_info['min_time_distance'])

            return None, 'no_challenge_mapping', debug_info, False

        except Exception:
            return None, 'error', None, False

    def finalize(self) -> None:
        """Close all output files and compress if needed."""
        print("\n" + "=" * 80)
        print("FINALIZING OUTPUT FILES")
        print("=" * 80)

        for template_id, f in self.output_files.items():
            f.close()

        if self.compress:
            for template_id, temp_path in self.temp_files.items():
                template_name = self.challenge_mapper.template_names.get(
                    template_id, f"template_{template_id}"
                )
                safe_name = re.sub(r'[^\w\-_]', '_', template_name)
                output_path = os.path.join(self.output_dir, f"{safe_name}.pcap.gz")

                print(f"  Compressing {safe_name}.pcap.gz...")
                with open(temp_path, 'rb') as f_in:
                    with gzip.open(output_path, 'wb', compresslevel=6) as f_out:
                        while True:
                            chunk = f_in.read(4 * 1024 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)

                os.remove(temp_path)
                print(f"  ✓ {safe_name}.pcap.gz")

    def print_detailed_stats(self) -> None:
        """Print comprehensive statistics."""
        total_time = time.time() - self.stats['processing_start']
        print("\n" + "=" * 80)
        print("SPLITTING STATISTICS")
        print("=" * 80)
        print(f"Total processing time:      {total_time:.2f}s")
        print(f"Total packets read:         {self.stats['total_packets_read']:,}")

        if total_time > 0:
            rate = self.stats['total_packets_read'] / total_time
            print(f"Processing rate:            {rate:,.0f} pkt/sec")

        print(f"Packets written:            {self.stats['packets_written']:,}")
        print(f"  - Exact match:            {self.stats['packets_written_exact']:,}")
        print(f"  - With tolerance:         {self.stats['packets_written_tolerance']:,}")
        print(f"Packets skipped:            {self.stats['packets_skipped']:,}")
        print(f"Output files created:       {len(self.output_files)}")
        print(f"Time tolerance:             {self.challenge_mapper.time_tolerance}s")
        print(f"Match strategy:             {'CLOSEST' if self.challenge_mapper.prefer_closest else 'FIRST'}")

        if self.stats['packet_time_range'][0] != float('inf'):
            min_ts = self.stats['packet_time_range'][0]
            max_ts = self.stats['packet_time_range'][1]
            print(f"\nPacket timestamp range:")
            print(f"  Earliest: {datetime.fromtimestamp(min_ts).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Latest:   {datetime.fromtimestamp(max_ts).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Span:     {(max_ts - min_ts) / 86400:.1f} days")

        if self.challenge_mapper.challenge_mappings:
            challenge_starts = [m['exact_start'] for m in self.challenge_mapper.challenge_mappings]
            challenge_stops = [m['exact_stop'] for m in self.challenge_mapper.challenge_mappings]
            print(f"\nChallenge timestamp range:")
            print(f"  Earliest: {datetime.fromtimestamp(min(challenge_starts)).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Latest:   {datetime.fromtimestamp(max(challenge_stops)).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Span:     {(max(challenge_stops) - min(challenge_starts)) / 86400:.1f} days")

        if self.stats['min_distances']:
            print("\n" + "=" * 80)
            print("UNMAPPED PACKET TIME DISTANCE ANALYSIS")
            print("=" * 80)
            print(f"Unmapped packets analyzed:  {len(self.stats['min_distances']):,}")

            max_dist = max(self.stats['min_distances'])
            mean_dist = sum(self.stats['min_distances']) / len(self.stats['min_distances'])
            median_dist = sorted(self.stats['min_distances'])[len(self.stats['min_distances']) // 2]

            print(f"Max(min(time_distance)):    {max_dist:.2f}s ({max_dist / 86400:.1f} days)")
            print(f"Mean(min(time_distance)):   {mean_dist:.2f}s ({mean_dist / 3600:.1f} hours)")
            print(f"Median(min(time_distance)): {median_dist:.2f}s ({median_dist / 60:.1f} minutes)")

            sorted_dists = sorted(self.stats['min_distances'])
            percentiles = [50, 75, 90, 95, 99]
            print("\nTime distance percentiles:")
            for p in percentiles:
                idx = int(len(sorted_dists) * p / 100)
                print(f"  {p}th percentile:          {sorted_dists[idx]:.2f}s")

            print("\nTime distance histogram:")
            bins = [0, 1, 5, 10, 30, 60, 300, 600, 3600, float('inf')]
            bin_labels = ['0-1s', '1-5s', '5-10s', '10-30s', '30-60s', '1-5min', '5-10min', '10-60min', '>60min']
            for i in range(len(bins) - 1):
                count = sum(1 for d in self.stats['min_distances'] if bins[i] <= d < bins[i + 1])
                if count > 0:
                    pct = (count / len(self.stats['min_distances'])) * 100
                    print(f"  {bin_labels[i]:12s}: {count:>8,} ({pct:5.1f}%)")

            if self.stats['extreme_misses']:
                print(f"\n⚠️  EXTREME TIME MISSES (>{3600}s / >1 hour): {len(self.stats['extreme_misses'])}")
                print("Top 5 worst misses:")
                sorted_misses = sorted(self.stats['extreme_misses'], key=lambda x: x['distance'], reverse=True)
                for i, miss in enumerate(sorted_misses[:5], 1):
                    print(f"  {i}. IP {miss['ip']}: {miss['distance']:.0f}s ({miss['distance'] / 86400:.1f} days)")
                    print(f"     Timestamp: {miss['time_str']}")
                    print(f"     Candidate challenges: {miss['matches']}")

        if self.stats['skip_reasons']:
            print("\n" + "=" * 80)
            print("PACKET SKIP REASONS")
            print("=" * 80)
            total_skipped = sum(self.stats['skip_reasons'].values())
            for reason, count in sorted(self.stats['skip_reasons'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_skipped) * 100 if total_skipped > 0 else 0
                desc = PacketClassifier.SKIP_REASONS.get(reason, reason)
                print(f"  {desc:30s}: {count:>8,} ({percentage:5.1f}%)")

        if self.stats['ip_protocols']:
            protocol_names = {
                1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 47: 'GRE',
                50: 'ESP', 51: 'AH', 89: 'OSPF', 132: 'SCTP'
            }
            print("\n" + "=" * 80)
            print("IP PROTOCOL DISTRIBUTION")
            print("=" * 80)
            total_protocols = sum(self.stats['ip_protocols'].values())
            for protocol, count in sorted(self.stats['ip_protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / total_protocols) * 100 if total_protocols > 0 else 0
                name = protocol_names.get(protocol, f'Proto_{protocol}')
                print(f"  {name:20s}: {count:>8,} ({percentage:5.1f}%)")

        if self.stats['packets_per_template']:
            print("\n" + "=" * 80)
            print("PACKETS PER TEMPLATE")
            print("=" * 80)
            for template_id in sorted(self.stats['packets_per_template'].keys()):
                count = self.stats['packets_per_template'][template_id]
                template_name = self.challenge_mapper.template_names.get(
                    template_id, f"template_{template_id}"
                )
                print(f"  {template_name:30s}: {count:,}")

        if self.log_unmapped and self.stats['unmapped_packets']:
            print("\n" + "=" * 80)
            print(f"UNMAPPED PACKET EXAMPLES (showing first 10 of {len(self.stats['unmapped_packets'])})")
            print("=" * 80)

            for i, packet_info in enumerate(self.stats['unmapped_packets'][:10]):
                print(f"\n{i + 1}. IP: {packet_info['ip']}")
                print(f"   Timestamp: {packet_info['packet_time_str']}")
                print(f"   Min distance: {packet_info['min_time_distance']:.2f}s")
                print(f"   Potential matches: {packet_info['total_mappings_checked']}")

                if packet_info['potential_matches']:
                    sorted_matches = sorted(packet_info['potential_matches'],
                                            key=lambda x: x['time_distance'])

                    print(f"   Closest candidates:")
                    for match in sorted_matches[:3]:
                        print(f"     • Template: {match['template_name']}")
                        print(f"       User: {match['username']}")
                        print(f"       Network: {match['network']}")
                        print(f"       Time distance: {match['time_distance']:.2f}s")
                        print(f"       Window: {match['exact_window']}")
                else:
                    print(f"   No candidates found for this IP")

            if len(self.stats['unmapped_packets']) > 10:
                remaining = len(self.stats['unmapped_packets']) - 10
                print(f"\n   ... and {remaining} more unmapped packets")

        print("=" * 80)


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_splitter.py <pcap_file(s)> [options]")
        print("\nDatabase Options (required):")
        print("  --db-host <host>          Database host (default: 10.0.0.102)")
        print("  --db-user <user>          Database username (required)")
        print("  --db-pass <pass>          Database password (required)")
        print("  --db-name <name>          Database name (default: ctf_challenger)")
        print("\nTime Options:")
        print("  --time-tolerance <sec>    Time tolerance (default: 5.0)")
        print("  --first-match             Use first match instead of closest (default: closest)")
        print("\nOutput Options:")
        print("  --out-dir <dir>           Output directory (default: ./split_pcaps)")
        print("  --no-compress             Don't compress output files")
        print("  --log-unmapped            Enable detailed unmapped packet logging")
        print("  --report <file>           Write JSON report")
        print("\nFiltering Options:")
        print("  --allowed-network <cidr>  CIDR to filter IPs (default: 10.128.0.0/9)")
        print("\nExamples:")
        print("  python pcap_splitter.py --db-user admin --db-pass secret --log-unmapped *.pcap.gz")
        print("  python pcap_splitter.py --db-user admin --db-pass secret --first-match *.pcap")
        sys.exit(1)

    input_files = []
    db_host = "10.0.0.102"
    db_user = None
    db_pass = None
    db_name = "ctf_challenger"
    out_dir = './split_pcaps'
    compress = True
    allowed_network = '10.128.0.0/9'
    time_tolerance = 5.0
    log_unmapped = False
    report_file = None
    prefer_closest = True

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
        elif arg == '--first-match':
            prefer_closest = False
            i += 1
        elif arg == '--out-dir' and i + 1 < len(sys.argv):
            out_dir = sys.argv[i + 1]
            i += 2
        elif arg == '--no-compress':
            compress = False
            i += 1
        elif arg == '--log-unmapped':
            log_unmapped = True
            i += 1
        elif arg == '--allowed-network' and i + 1 < len(sys.argv):
            allowed_network = sys.argv[i + 1]
            i += 2
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
        print("Error: Database credentials required")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    challenge_mapper = ChallengeMapper(
        db_host=db_host,
        db_user=db_user,
        db_pass=db_pass,
        db_name=db_name,
        time_tolerance=time_tolerance,
        prefer_closest=prefer_closest
    )
    challenge_mapper.connect()
    challenge_mapper.load_challenge_mappings()

    if not challenge_mapper.challenge_mappings:
        print("\nWarning: No challenge mappings found")
        challenge_mapper.close()
        sys.exit(0)

    print("\n" + "=" * 80)
    print("PCAP CHALLENGE SPLITTER")
    print("=" * 80)
    print(f"Configuration:")
    print(f"  Input files:      {len(all_files)}")
    print(f"  Output directory: {out_dir}")
    print(f"  Time tolerance:   {time_tolerance}s")
    print(f"  Match strategy:   {'CLOSEST MATCH' if prefer_closest else 'FIRST MATCH'}")
    print(f"  Challenge maps:   {len(challenge_mapper.challenge_mappings)}")
    print(f"  IP ranges:        {len(challenge_mapper.ip_ranges)}")
    print(f"  Debug logging:    {'ENABLED' if log_unmapped else 'disabled'}")
    print("=" * 80)

    start_time = time.time()

    splitter = PCAPSplitter(
        challenge_mapper=challenge_mapper,
        output_dir=out_dir,
        compress=compress,
        allowed_networks=[allowed_network],
        log_unmapped=log_unmapped
    )

    for filepath in all_files:
        splitter.split_pcap(filepath)

    splitter.finalize()
    splitter.print_detailed_stats()

    if report_file:
        report = {
            'configuration': {
                'allowed_network': allowed_network,
                'time_tolerance': time_tolerance,
                'prefer_closest': prefer_closest,
                'log_unmapped': log_unmapped
            },
            'statistics': {
                'total_time': time.time() - start_time,
                'total_packets_read': splitter.stats['total_packets_read'],
                'packets_written': splitter.stats['packets_written'],
                'packets_written_exact': splitter.stats['packets_written_exact'],
                'packets_written_tolerance': splitter.stats['packets_written_tolerance'],
                'packets_skipped': splitter.stats['packets_skipped'],
                'max_min_time_distance': max(splitter.stats['min_distances']) if splitter.stats[
                    'min_distances'] else None,
                'mean_min_time_distance': sum(splitter.stats['min_distances']) / len(splitter.stats['min_distances']) if
                splitter.stats['min_distances'] else None,
            },
            'templates': {
                tid: {
                    'name': name,
                    'packets': splitter.stats['packets_per_template'].get(tid, 0)
                }
                for tid, name in challenge_mapper.template_names.items()
            },
            'skip_reasons': dict(splitter.stats['skip_reasons']),
            'ip_protocols': dict(splitter.stats['ip_protocols']),
            'unmapped_packets': splitter.stats['unmapped_packets'] if log_unmapped else []
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n✓ Report written to {report_file}")

    total_time = time.time() - start_time

    challenge_mapper.close()

    print("\n" + "=" * 80)
    print("COMPLETED")
    print("=" * 80)
    print(f"Total time: {total_time:.2f}s")
    print(f"Files processed: {len(all_files)}")
    print(f"Output files: {len(splitter.output_files)}")
    if splitter.stats['packets_written_tolerance'] > 0:
        print(f"\n⚠  {splitter.stats['packets_written_tolerance']:,} packets matched using time tolerance")
    if splitter.stats['min_distances']:
        print(f"\n📊 Max(min(time_distance)) for unmapped packets: {max(splitter.stats['min_distances']):.2f}s")


if __name__ == '__main__':
    main()