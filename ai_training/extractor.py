#!/usr/bin/env python3
"""
Network flow feature extractor from PCAP files.
Supports .pcap, .gz, and .zip formats with bidirectional flow analysis.
"""

import gzip
import zipfile
import os
import csv
import sys
import glob
import tempfile
import struct
import socket
import time
from collections import deque
from typing import Dict, List, Any, Set
from enum import Enum


class TCPState(Enum):
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_WAIT = 4


class PCAPParser:
    def __init__(self, inactive_timeout: int = 15, active_timeout: int = 300):
        self.inactive_timeout = inactive_timeout
        self.active_timeout = active_timeout
        self.flows: Dict[str, Dict] = {}
        self.completed_flows: List[Dict] = []
        self.last_timeout_check = 0
        self.timeout_check_interval = 10000
        self.flow_export_batch = 1000
        self.stats = {
            'total_packets': 0,
            'flows_created': 0,
            'flows_expired_inactive': 0,
            'flows_expired_active': 0,
            'flows_expired_tcp_fin': 0,
            'flows_expired_tcp_rst': 0,
            'processing_start': time.time()
        }

    def _create_flow(self) -> Dict:
        return {
            'start_time': None,
            'end_time': None,
            'last_packet_time': None,
            'bytes_src_to_dst': 0,
            'bytes_dst_to_src': 0,
            'pkts_src_to_dst': 0,
            'pkts_dst_to_src': 0,
            'retrans_in_bytes': 0,
            'retrans_out_bytes': 0,
            'retrans_in_pkts': 0,
            'retrans_out_pkts': 0,
            'tcp_flags': set(),
            'client_tcp_flags': set(),
            'server_tcp_flags': set(),
            'tcp_state': TCPState.CLOSED,
            'min_ttl': 255,
            'max_ttl': 0,
            'pkt_lengths': deque(maxlen=1000),
            'tcp_win_sizes': deque(maxlen=1000),
            'icmp_types': set(),
            'dns_queries': set(),
            'dns_answers': set(),
            'ftp_commands': set(),
            'seen_seq_forward': {},
            'seen_seq_backward': {},
            'src_timestamps': deque(maxlen=1000),
            'dst_timestamps': deque(maxlen=1000),
            'src_ip': '',
            'dst_ip': '',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0
        }

    def parse_pcap_file(self, filepath: str) -> None:
        try:
            file_size = os.path.getsize(filepath) / (1024 * 1024)
            print(f"File size: {file_size:.2f} MB")

            with open(filepath, 'rb', buffering=1024 * 1024) as f:
                magic = struct.unpack('I', f.read(4))[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP format: {filepath}")
                    return

                f.read(20)

                packet_count = 0
                batch_size = 50000

                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        endian + 'IIII', packet_header
                    )
                    timestamp = ts_sec + ts_usec / 1000000.0

                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    self.parse_packet(packet_data, timestamp, orig_len)
                    self.stats['total_packets'] += 1
                    packet_count += 1

                    if packet_count % self.timeout_check_interval == 0:
                        self._check_flow_timeouts(timestamp)

                    if self.stats['total_packets'] % 100000 == 0:
                        elapsed = time.time() - self.stats['processing_start']
                        rate = self.stats['total_packets'] / elapsed if elapsed > 0 else 0
                        print(f"  Processed {self.stats['total_packets']:,} packets, "
                              f"{len(self.flows):,} active flows, "
                              f"{rate:,.0f} pkt/sec", end='\r')

                    if packet_count % batch_size == 0:
                        if len(self.completed_flows) >= self.flow_export_batch:
                            self._export_completed_flows_batch()

                self._check_flow_timeouts(timestamp, force=True)
                self._export_all_flows()
                print()

        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

    def _check_flow_timeouts(self, current_time: float, force: bool = False) -> None:
        expired_flows = []

        for flow_id, flow in list(self.flows.items()):
            if flow['last_packet_time'] is None:
                continue

            inactive_time = current_time - flow['last_packet_time']
            if inactive_time >= self.inactive_timeout:
                expired_flows.append((flow_id, 'inactive'))
                continue

            active_time = current_time - flow['start_time']
            if active_time >= self.active_timeout:
                expired_flows.append((flow_id, 'active'))

        for flow_id, reason in expired_flows:
            self._export_flow(flow_id, reason)

    def parse_packet(self, data: bytes, timestamp: float, orig_len: int) -> None:
        try:
            if len(data) < 14:
                return

            eth_type = (data[12] << 8) | data[13]

            if eth_type == 0x0800:
                self.parse_ipv4(data[14:], timestamp, orig_len)

        except Exception:
            pass

    def parse_ipv4(self, data: bytes, timestamp: float, orig_len: int) -> None:
        if len(data) < 20:
            return

        version_ihl = data[0]
        ihl = (version_ihl & 0x0F) * 4
        ttl = data[8]
        protocol = data[9]

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        ip_data = data[ihl:]

        if protocol == 6:
            self.parse_tcp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)
        elif protocol == 17:
            self.parse_udp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)
        elif protocol == 1:
            self.parse_icmp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)

    def parse_tcp(self, data: bytes, src_ip: str, dst_ip: str,
                  timestamp: float, ttl: int, orig_len: int) -> None:
        if len(data) < 20:
            return

        src_port = (data[0] << 8) | data[1]
        dst_port = (data[2] << 8) | data[3]
        seq_num = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]
        flags = data[13]
        data_offset = (data[12] >> 4) * 4
        window = (data[14] << 8) | data[15]

        tcp_payload_len = len(data) - data_offset

        FIN = flags & 0x01
        RST = flags & 0x04

        flow_id = self.create_flow_id(src_ip, dst_ip, src_port, dst_port, 6)

        if flow_id not in self.flows:
            self.flows[flow_id] = self._create_flow()
            self.stats['flows_created'] += 1

        flow = self.flows[flow_id]
        is_forward = (src_ip, src_port) < (dst_ip, dst_port)

        if flow['start_time'] is None:
            flow.update({
                'start_time': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 6
            })

        if RST:
            flow['tcp_state'] = TCPState.CLOSED
            self._export_flow(flow_id, 'tcp_rst')
            return
        elif FIN and flow['tcp_state'] == TCPState.ESTABLISHED:
            self._export_flow(flow_id, 'tcp_fin')
            return

        is_retrans = False
        if tcp_payload_len > 0:
            seq_dict = flow['seen_seq_forward'] if is_forward else flow['seen_seq_backward']
            if seq_num in seq_dict:
                is_retrans = True
                if is_forward:
                    flow['retrans_out_pkts'] += 1
                    flow['retrans_out_bytes'] += orig_len
                else:
                    flow['retrans_in_pkts'] += 1
                    flow['retrans_in_bytes'] += orig_len
            else:
                if len(seq_dict) > 1000:
                    self._clean_old_sequences(seq_dict, timestamp)
                seq_dict[seq_num] = timestamp

        if not is_retrans:
            if is_forward:
                flow['bytes_src_to_dst'] += orig_len
                flow['pkts_src_to_dst'] += 1
                flow['client_tcp_flags'].add(flags)
                flow['src_timestamps'].append(timestamp)
            else:
                flow['bytes_dst_to_src'] += orig_len
                flow['pkts_dst_to_src'] += 1
                flow['server_tcp_flags'].add(flags)
                flow['dst_timestamps'].append(timestamp)

        flow['tcp_flags'].add(flags)
        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)
        flow['end_time'] = timestamp
        flow['last_packet_time'] = timestamp
        flow['tcp_win_sizes'].append(window)

    def _clean_old_sequences(self, seq_dict: Dict[int, float], current_time: float) -> None:
        cutoff_time = current_time - 60
        keys_to_remove = [k for k, v in seq_dict.items() if v < cutoff_time]
        for k in keys_to_remove:
            del seq_dict[k]

    def parse_udp(self, data: bytes, src_ip: str, dst_ip: str,
                  timestamp: float, ttl: int, orig_len: int) -> None:
        if len(data) < 8:
            return

        src_port = (data[0] << 8) | data[1]
        dst_port = (data[2] << 8) | data[3]

        flow_id = self.create_flow_id(src_ip, dst_ip, src_port, dst_port, 17)

        if flow_id not in self.flows:
            self.flows[flow_id] = self._create_flow()
            self.stats['flows_created'] += 1

        flow = self.flows[flow_id]
        is_forward = (src_ip, src_port) < (dst_ip, dst_port)

        if flow['start_time'] is None:
            flow.update({
                'start_time': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 17
            })

        if is_forward:
            flow['bytes_src_to_dst'] += orig_len
            flow['pkts_src_to_dst'] += 1
            flow['src_timestamps'].append(timestamp)
        else:
            flow['bytes_dst_to_src'] += orig_len
            flow['pkts_dst_to_src'] += 1
            flow['dst_timestamps'].append(timestamp)

        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)
        flow['end_time'] = timestamp
        flow['last_packet_time'] = timestamp

        if src_port == 53 or dst_port == 53:
            self.parse_dns(data[8:], flow, src_port == 53)

    def parse_icmp(self, data: bytes, src_ip: str, dst_ip: str,
                   timestamp: float, ttl: int, orig_len: int) -> None:
        if len(data) < 8:
            return

        icmp_type = data[0]

        flow_id = self.create_flow_id(src_ip, dst_ip, 0, 0, 1)

        if flow_id not in self.flows:
            self.flows[flow_id] = self._create_flow()
            self.stats['flows_created'] += 1

        flow = self.flows[flow_id]
        is_forward = src_ip < dst_ip

        if flow['start_time'] is None:
            flow.update({
                'start_time': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 1
            })

        flow['icmp_types'].add(icmp_type)

        if is_forward:
            flow['bytes_src_to_dst'] += orig_len
            flow['pkts_src_to_dst'] += 1
            flow['src_timestamps'].append(timestamp)
        else:
            flow['bytes_dst_to_src'] += orig_len
            flow['pkts_dst_to_src'] += 1
            flow['dst_timestamps'].append(timestamp)

        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)
        flow['end_time'] = timestamp
        flow['last_packet_time'] = timestamp

    def parse_dns(self, data: bytes, flow: Dict, is_response: bool = False) -> None:
        try:
            if len(data) < 12:
                return

            transaction_id = (data[0] << 8) | data[1]
            flags = (data[2] << 8) | data[3]
            qr = (flags >> 15) & 1

            if qr == 0:
                flow['dns_queries'].add(transaction_id)
            else:
                flow['dns_answers'].add(transaction_id)
        except Exception:
            pass

    def _export_flow(self, flow_id: str, reason: str) -> None:
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            flow['export_reason'] = reason

            self._calculate_iat_stats(flow)
            self.completed_flows.append(flow)
            del self.flows[flow_id]

            if reason == 'inactive':
                self.stats['flows_expired_inactive'] += 1
            elif reason == 'active':
                self.stats['flows_expired_active'] += 1
            elif reason == 'tcp_fin':
                self.stats['flows_expired_tcp_fin'] += 1
            elif reason == 'tcp_rst':
                self.stats['flows_expired_tcp_rst'] += 1

    def _calculate_iat_stats(self, flow: Dict) -> None:
        src_times = list(flow['src_timestamps'])
        dst_times = list(flow['dst_timestamps'])

        if len(src_times) > 1:
            src_iats = [src_times[i + 1] - src_times[i] for i in range(len(src_times) - 1)]
            flow['src_iat_min'] = min(src_iats) * 1000 if src_iats else 0
            flow['src_iat_max'] = max(src_iats) * 1000 if src_iats else 0
            flow['src_iat_avg'] = sum(src_iats) / len(src_iats) * 1000 if src_iats else 0
            flow['src_iat_std'] = self.std_dev(src_iats) * 1000 if src_iats else 0

        if len(dst_times) > 1:
            dst_iats = [dst_times[i + 1] - dst_times[i] for i in range(len(dst_times) - 1)]
            flow['dst_iat_min'] = min(dst_iats) * 1000 if dst_iats else 0
            flow['dst_iat_max'] = max(dst_iats) * 1000 if dst_iats else 0
            flow['dst_iat_avg'] = sum(dst_iats) / len(dst_iats) * 1000 if dst_iats else 0
            flow['dst_iat_std'] = self.std_dev(dst_iats) * 1000 if dst_iats else 0

        flow.setdefault('src_iat_min', 0)
        flow.setdefault('src_iat_max', 0)
        flow.setdefault('src_iat_avg', 0)
        flow.setdefault('src_iat_std', 0)
        flow.setdefault('dst_iat_min', 0)
        flow.setdefault('dst_iat_max', 0)
        flow.setdefault('dst_iat_avg', 0)
        flow.setdefault('dst_iat_std', 0)

    def _export_completed_flows_batch(self) -> None:
        if hasattr(self, '_current_output_file') and self.completed_flows:
            features = self.calculate_features_batch(self.completed_flows)
            self.write_csv_batch(features, self._current_output_file)
            self.completed_flows.clear()

    def _export_all_flows(self) -> None:
        for flow_id in list(self.flows.keys()):
            self._export_flow(flow_id, 'eof')

    def create_flow_id(self, src_ip: str, dst_ip: str, src_port: int,
                       dst_port: int, protocol: int) -> str:
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def calculate_features_batch(self, flows: List[Dict]) -> List[Dict[str, Any]]:
        features_list = []
        for flow in flows:
            if flow['pkts_src_to_dst'] > 0 or flow['pkts_dst_to_src'] > 0:
                features = self.extract_flow_features(flow)
                features_list.append(features)
        return features_list

    def extract_flow_features(self, flow: Dict) -> Dict[str, Any]:
        features = {}

        features['IPV4_SRC_ADDR'] = flow.get('src_ip', '')
        features['IPV4_DST_ADDR'] = flow.get('dst_ip', '')
        features['L4_SRC_PORT'] = flow.get('src_port', 0)
        features['L4_DST_PORT'] = flow.get('dst_port', 0)
        features['PROTOCOL'] = flow.get('protocol', 0)
        features['L7_PROTO'] = self.detect_l7_proto(flow)

        features['IN_BYTES'] = flow['bytes_src_to_dst']
        features['OUT_BYTES'] = flow['bytes_dst_to_src']
        features['IN_PKTS'] = flow['pkts_src_to_dst']
        features['OUT_PKTS'] = flow['pkts_dst_to_src']

        duration = 0
        if flow['start_time'] and flow['end_time']:
            duration = flow['end_time'] - flow['start_time']

        features['FLOW_DURATION_MILLISECONDS'] = int(duration * 1000)
        features['DURATION_IN'] = int(duration * 1000)
        features['DURATION_OUT'] = int(duration * 1000)

        features['FLOW_START_MILLISECONDS'] = int(flow['start_time'] * 1000) if flow['start_time'] else 0
        features['FLOW_END_MILLISECONDS'] = int(flow['end_time'] * 1000) if flow['end_time'] else 0

        features['MIN_TTL'] = flow['min_ttl']
        features['MAX_TTL'] = flow['max_ttl']

        pkt_lens = list(flow['pkt_lengths'])
        features['LONGEST_FLOW_PKT'] = max(pkt_lens) if pkt_lens else 0
        features['SHORTEST_FLOW_PKT'] = min(pkt_lens) if pkt_lens else 0
        features['MIN_IP_PKT_LEN'] = min(pkt_lens) if pkt_lens else 0
        features['MAX_IP_PKT_LEN'] = max(pkt_lens) if pkt_lens else 0

        features['SRC_TO_DST_SECOND_BYTES'] = flow['bytes_src_to_dst']
        features['DST_TO_SRC_SECOND_BYTES'] = flow['bytes_dst_to_src']

        features['RETRANSMITTED_IN_BYTES'] = flow['retrans_in_bytes']
        features['RETRANSMITTED_OUT_BYTES'] = flow['retrans_out_bytes']
        features['RETRANSMITTED_IN_PKTS'] = flow['retrans_in_pkts']
        features['RETRANSMITTED_OUT_PKTS'] = flow['retrans_out_pkts']

        if duration > 0:
            features['SRC_TO_DST_AVG_THROUGHPUT'] = flow['bytes_src_to_dst'] / duration
            features['DST_TO_SRC_AVG_THROUGHPUT'] = flow['bytes_dst_to_src'] / duration
        else:
            features['SRC_TO_DST_AVG_THROUGHPUT'] = 0
            features['DST_TO_SRC_AVG_THROUGHPUT'] = 0

        features['NUM_PKTS_UP_TO_128_BYTES'] = sum(1 for l in pkt_lens if l <= 128)
        features['NUM_PKTS_128_TO_256_BYTES'] = sum(1 for l in pkt_lens if 128 < l <= 256)
        features['NUM_PKTS_256_TO_512_BYTES'] = sum(1 for l in pkt_lens if 256 < l <= 512)
        features['NUM_PKTS_512_TO_1024_BYTES'] = sum(1 for l in pkt_lens if 512 < l <= 1024)
        features['NUM_PKTS_1024_TO_1514_BYTES'] = sum(1 for l in pkt_lens if 1024 < l <= 1514)

        features['TCP_FLAGS'] = self.flags_to_int(flow['tcp_flags'])
        features['CLIENT_TCP_FLAGS'] = self.flags_to_int(flow['client_tcp_flags'])
        features['SERVER_TCP_FLAGS'] = self.flags_to_int(flow['server_tcp_flags'])

        tcp_wins = list(flow['tcp_win_sizes'])
        features['TCP_WIN_MAX_IN'] = max(tcp_wins) if tcp_wins else 0
        features['TCP_WIN_MAX_OUT'] = max(tcp_wins) if tcp_wins else 0

        if flow['icmp_types']:
            icmp_type_counts = {}
            for icmp_type in flow['icmp_types']:
                icmp_type_counts[icmp_type] = icmp_type_counts.get(icmp_type, 0) + 1

            if icmp_type_counts:
                most_common_type = max(icmp_type_counts, key=icmp_type_counts.get)
                features['ICMP_TYPE'] = most_common_type
                features['ICMP_IPV4_TYPE'] = most_common_type
            else:
                features['ICMP_TYPE'] = 0
                features['ICMP_IPV4_TYPE'] = 0
        else:
            features['ICMP_TYPE'] = 0
            features['ICMP_IPV4_TYPE'] = 0

        features['DNS_QUERY_ID'] = len(flow['dns_queries'])
        features['DNS_QUERY_TYPE'] = 1 if flow['dns_queries'] else 0
        features['DNS_TTL_ANSWER'] = len(flow['dns_answers'])

        ftp_code = 0
        if flow['ftp_commands']:
            ftp_code = len(flow['ftp_commands'])
        elif flow.get('protocol') == 6:
            src_port = flow.get('src_port', 0)
            dst_port = flow.get('dst_port', 0)
            if src_port == 21 or dst_port == 21:
                ftp_code = 1

        features['FTP_COMMAND_RET_CODE'] = ftp_code

        features['SRC_TO_DST_IAT_MIN'] = flow.get('src_iat_min', 0)
        features['SRC_TO_DST_IAT_MAX'] = flow.get('src_iat_max', 0)
        features['SRC_TO_DST_IAT_AVG'] = flow.get('src_iat_avg', 0)
        features['SRC_TO_DST_IAT_STDDEV'] = flow.get('src_iat_std', 0)
        features['DST_TO_SRC_IAT_MIN'] = flow.get('dst_iat_min', 0)
        features['DST_TO_SRC_IAT_MAX'] = flow.get('dst_iat_max', 0)
        features['DST_TO_SRC_IAT_AVG'] = flow.get('dst_iat_avg', 0)
        features['DST_TO_SRC_IAT_STDDEV'] = flow.get('dst_iat_std', 0)

        return features

    def print_stats(self) -> None:
        total_time = time.time() - self.stats['processing_start']
        print("\n" + "=" * 80)
        print("PERFORMANCE STATISTICS")
        print("=" * 80)
        print(f"Total processing time:      {total_time:.2f}s")
        print(f"Total packets processed:    {self.stats['total_packets']:,}")
        if total_time > 0:
            print(f"Processing rate:            {self.stats['total_packets'] / total_time:,.0f} pkt/sec")
        print(f"Total flows created:        {self.stats['flows_created']:,}")
        print(f"Memory usage:               {len(self.flows):,} active flows")
        print(f"Completed flows:            {len(self.completed_flows):,}")
        print("=" * 80)

    @staticmethod
    def std_dev(values: List[float]) -> float:
        if not values:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    @staticmethod
    def flags_to_int(flags_set: Set[int]) -> int:
        result = 0
        for flag in flags_set:
            result |= flag
        return result

    @staticmethod
    def detect_l7_proto(flow: Dict) -> int:
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)

        if src_port == 80 or dst_port == 80:
            return 7
        elif src_port == 443 or dst_port == 443:
            return 91
        elif src_port == 53 or dst_port == 53:
            return 5
        elif src_port == 21 or dst_port == 21:
            return 1
        return 0

    def write_csv_batch(self, features_list: List[Dict[str, Any]], output_file: str) -> None:
        if not features_list:
            return

        file_exists = os.path.exists(output_file)

        with open(output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=features_list[0].keys())

            if not file_exists:
                writer.writeheader()

            chunk_size = 1000
            for i in range(0, len(features_list), chunk_size):
                chunk = features_list[i:i + chunk_size]
                writer.writerows(chunk)


def process_file(filepath: str, output_csv: str, inactive_timeout: int = 15,
                 active_timeout: int = 300) -> None:
    print(f"Processing: {filepath}")

    parser = PCAPParser(inactive_timeout, active_timeout)
    temp_file = None

    try:
        if filepath.endswith('.gz'):
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file_obj:
                temp_file = temp_file_obj.name

            with gzip.open(filepath, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    while True:
                        chunk = f_in.read(1024 * 1024)
                        if not chunk:
                            break
                        f_out.write(chunk)

            parser.parse_pcap_file(temp_file)

        elif filepath.endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                for name in zip_ref.namelist():
                    if name.endswith('.pcap') or name.endswith('.cap'):
                        with tempfile.TemporaryDirectory() as temp_dir:
                            temp_path = os.path.join(temp_dir, os.path.basename(name))
                            with zip_ref.open(name) as source:
                                with open(temp_path, 'wb') as target:
                                    while True:
                                        chunk = source.read(1024 * 1024)
                                        if not chunk:
                                            break
                                        target.write(chunk)
                            parser.parse_pcap_file(temp_path)
        else:
            parser.parse_pcap_file(filepath)

        if parser.completed_flows:
            features = parser.calculate_features_batch(parser.completed_flows)
            if features:
                parser.write_csv_batch(features, output_csv)

        parser.print_stats()
        print(f"✓ {len(parser.completed_flows)} flows extracted")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_extractor.py <pcap_file(s)> [options]")
        print("\nOptions:")
        print("  --output <file>           Output CSV file (default: features.csv)")
        print("  --inactive-timeout <sec>  Inactive timeout (default: 15)")
        print("  --active-timeout <sec>    Active timeout (default: 300)")
        print("\nExamples:")
        print("  python pcap_extractor.py traffic.pcap")
        print("  python pcap_extractor.py *.pcap.gz --output results.csv")
        print("  python pcap_extractor.py file.pcap --inactive-timeout 30")
        sys.exit(1)

    output_csv = 'features.csv'
    inactive_timeout = 15
    active_timeout = 300
    input_files = []

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--output' and i + 1 < len(sys.argv):
            output_csv = sys.argv[i + 1]
            i += 2
        elif arg == '--inactive-timeout' and i + 1 < len(sys.argv):
            inactive_timeout = int(sys.argv[i + 1])
            i += 2
        elif arg == '--active-timeout' and i + 1 < len(sys.argv):
            active_timeout = int(sys.argv[i + 1])
            i += 2
        else:
            input_files.append(arg)
            i += 1

    if not input_files:
        print("No input files specified!")
        sys.exit(1)

    if os.path.exists(output_csv):
        response = input(f"The file '{output_csv}' already exists. Overwrite it? [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            print("Aborted by user.")
            sys.exit(0)
        os.remove(output_csv)
        print(f"Removed existing {output_csv}")

    all_files = []
    for pattern in input_files:
        all_files.extend(glob.glob(pattern))

    if not all_files:
        print("No files found!")
        sys.exit(1)

    print("=" * 80)
    print("PCAP FEATURE EXTRACTOR")
    print("=" * 80)
    print(f"Configuration:")
    print(f"  Inactive timeout: {inactive_timeout}s")
    print(f"  Active timeout:   {active_timeout}s")
    print(f"  Output file:      {output_csv}")
    print(f"  Input files:      {len(all_files)}")
    print("=" * 80 + "\n")

    start_time = time.time()

    for filepath in all_files:
        process_file(filepath, output_csv, inactive_timeout, active_timeout)

    total_time = time.time() - start_time
    print("\n" + "=" * 80)
    print("COMPLETED!")
    print("=" * 80)
    print(f"Total processing time: {total_time:.2f}s")
    print(f"Features saved to: {output_csv}")


if __name__ == '__main__':
    main()