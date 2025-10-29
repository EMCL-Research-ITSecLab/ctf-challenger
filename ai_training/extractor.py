#!/usr/bin/env python3
"""
PCAP Feature Extractor

Extracts network flow features from PCAP files (supports .pcap, .gz, .zip formats).
Implements bidirectional flow analysis with retransmission detection and
protocol-specific feature extraction.
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
from collections import defaultdict
from typing import Dict, List, Any, Optional, Set


class PCAPParser:
    """Parser for PCAP files with flow-based feature extraction."""

    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'end_time': None,
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
            'min_ttl': 255,
            'max_ttl': 0,
            'pkt_lengths': [],
            'iat_src_to_dst': [],
            'iat_dst_to_src': [],
            'tcp_win_sizes': [],
            'icmp_types': set(),
            'dns_queries': set(),
            'dns_answers': set(),
            'ftp_commands': set(),
            'seen_seq_forward': {},
            'seen_seq_backward': {}
        })

    def parse_pcap_file(self, filepath: str) -> None:
        """Parse PCAP file and extract packets."""
        try:
            with open(filepath, 'rb') as f:
                magic = struct.unpack('I', f.read(4))[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP format: {filepath}")
                    return

                f.read(20)

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

        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

    def parse_packet(self, data: bytes, timestamp: float, orig_len: int) -> None:
        """Parse individual packet from Ethernet frame."""
        try:
            if len(data) < 14:
                return

            eth_type = struct.unpack('!H', data[12:14])[0]

            if eth_type == 0x0800:  # IPv4
                self.parse_ipv4(data[14:], timestamp, orig_len)

        except Exception:
            pass

    def parse_ipv4(self, data: bytes, timestamp: float, orig_len: int) -> None:
        """Parse IPv4 packet and dispatch to protocol handlers."""
        if len(data) < 20:
            return

        version_ihl = data[0]
        ihl = (version_ihl & 0x0F) * 4
        ttl = data[8]
        protocol = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        ip_data = data[ihl:]

        if protocol == 6:  # TCP
            self.parse_tcp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)
        elif protocol == 17:  # UDP
            self.parse_udp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)
        elif protocol == 1:  # ICMP
            self.parse_icmp(ip_data, src_ip, dst_ip, timestamp, ttl, orig_len)

    def parse_tcp(self, data: bytes, src_ip: str, dst_ip: str,
                  timestamp: float, ttl: int, orig_len: int) -> None:
        """Parse TCP packet with retransmission detection."""
        if len(data) < 20:
            return

        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]
        seq_num = struct.unpack('!I', data[4:8])[0]
        ack_num = struct.unpack('!I', data[8:12])[0]
        data_offset = (data[12] >> 4) * 4
        flags = data[13]
        window = struct.unpack('!H', data[14:16])[0]

        tcp_payload_len = len(data) - data_offset

        flow_id = self.create_flow_id(src_ip, dst_ip, src_port, dst_port, 6)
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
                seq_dict[seq_num] = (timestamp, tcp_payload_len)

        pkt_info = {
            'timestamp': timestamp,
            'is_forward': is_forward,
            'length': orig_len,
            'ttl': ttl,
            'seq': seq_num,
            'ack': ack_num,
            'flags': flags,
            'window': window,
            'is_retrans': is_retrans
        }
        flow['packets'].append(pkt_info)

        flow['end_time'] = timestamp

        if not is_retrans:
            if is_forward:
                flow['bytes_src_to_dst'] += orig_len
                flow['pkts_src_to_dst'] += 1
                flow['client_tcp_flags'].add(flags)
            else:
                flow['bytes_dst_to_src'] += orig_len
                flow['pkts_dst_to_src'] += 1
                flow['server_tcp_flags'].add(flags)

        flow['tcp_flags'].add(flags)
        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)
        flow['tcp_win_sizes'].append(window)

    def parse_udp(self, data: bytes, src_ip: str, dst_ip: str,
                  timestamp: float, ttl: int, orig_len: int) -> None:
        """Parse UDP packet."""
        if len(data) < 8:
            return

        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]

        flow_id = self.create_flow_id(src_ip, dst_ip, src_port, dst_port, 17)
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

        pkt_info = {
            'timestamp': timestamp,
            'is_forward': is_forward,
            'length': orig_len,
            'ttl': ttl
        }
        flow['packets'].append(pkt_info)

        flow['end_time'] = timestamp

        if is_forward:
            flow['bytes_src_to_dst'] += orig_len
            flow['pkts_src_to_dst'] += 1
        else:
            flow['bytes_dst_to_src'] += orig_len
            flow['pkts_dst_to_src'] += 1

        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)

        if src_port == 53 or dst_port == 53:
            self.parse_dns(data[8:], flow, src_port == 53)

        if src_port == 20 or dst_port == 20:
            flow['ftp_commands'].add('DATA')

    def parse_icmp(self, data: bytes, src_ip: str, dst_ip: str,
                   timestamp: float, ttl: int, orig_len: int) -> None:
        """Parse ICMP packet."""
        if len(data) < 8:
            return

        icmp_type = data[0]
        icmp_code = data[1]

        flow_id = self.create_flow_id(src_ip, dst_ip, 0, 0, 1)
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

        pkt_info = {
            'timestamp': timestamp,
            'is_forward': is_forward,
            'length': orig_len,
            'ttl': ttl,
            'icmp_type': icmp_type,
            'icmp_code': icmp_code
        }
        flow['packets'].append(pkt_info)

        flow['icmp_types'].add(icmp_type)
        flow['end_time'] = timestamp

        if is_forward:
            flow['bytes_src_to_dst'] += orig_len
            flow['pkts_src_to_dst'] += 1
        else:
            flow['bytes_dst_to_src'] += orig_len
            flow['pkts_dst_to_src'] += 1

        flow['min_ttl'] = min(flow['min_ttl'], ttl)
        flow['max_ttl'] = max(flow['max_ttl'], ttl)
        flow['pkt_lengths'].append(orig_len)

    def parse_dns(self, data: bytes, flow: Dict, is_response: bool = False) -> None:
        """Parse DNS packet."""
        try:
            if len(data) < 12:
                return

            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            qr = (flags >> 15) & 1

            if qr == 0:
                flow['dns_queries'].add(transaction_id)
            else:
                flow['dns_answers'].add(transaction_id)
        except Exception:
            pass

    def create_flow_id(self, src_ip: str, dst_ip: str, src_port: int,
                       dst_port: int, protocol: int) -> str:
        """Create unique bidirectional flow identifier."""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def calculate_features(self) -> List[Dict[str, Any]]:
        """Calculate features for all flows."""
        features_list = []

        for flow_id, flow in self.flows.items():
            if not flow['packets']:
                continue

            features = self.extract_flow_features(flow)
            features_list.append(features)

        return features_list

    def extract_flow_features(self, flow: Dict) -> Dict[str, Any]:
        """Extract comprehensive feature set from flow."""
        features = {}

        features['IPV4_SRC_ADDR'] = flow.get('src_ip', '')
        features['IPV4_DST_ADDR'] = flow.get('dst_ip', '')
        features['L4_SRC_PORT'] = flow.get('src_port', 0)
        features['L4_DST_PORT'] = flow.get('dst_port', 0)
        features['PROTOCOL'] = flow.get('protocol', 0)
        features['L7_PROTO'] = self.detect_l7_proto(flow)

        features['IN_BYTES'] = flow['bytes_dst_to_src']
        features['OUT_BYTES'] = flow['bytes_src_to_dst']
        features['IN_PKTS'] = flow['pkts_dst_to_src']
        features['OUT_PKTS'] = flow['pkts_src_to_dst']

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

        pkt_lens = flow['pkt_lengths']
        features['LONGEST_FLOW_PKT'] = max(pkt_lens) if pkt_lens else 0
        features['SHORTEST_FLOW_PKT'] = min(pkt_lens) if pkt_lens else 0
        features['MIN_IP_PKT_LEN'] = min(pkt_lens) if pkt_lens else 0
        features['MAX_IP_PKT_LEN'] = max(pkt_lens) if pkt_lens else 0

        self.calculate_iat(flow)

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

        tcp_wins = flow['tcp_win_sizes']
        features['TCP_WIN_MAX_IN'] = max(tcp_wins) if tcp_wins else 0
        features['TCP_WIN_MAX_OUT'] = max(tcp_wins) if tcp_wins else 0

        if flow['icmp_types']:
            icmp_type_counts = {}
            for pkt in flow['packets']:
                if 'icmp_type' in pkt:
                    icmp_type = pkt['icmp_type']
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

    def calculate_iat(self, flow: Dict) -> None:
        """Calculate inter-arrival time statistics."""
        src_times = []
        dst_times = []

        for pkt in flow['packets']:
            if pkt['is_forward']:
                src_times.append(pkt['timestamp'])
            else:
                dst_times.append(pkt['timestamp'])

        if len(src_times) > 1:
            src_iats = [src_times[i + 1] - src_times[i] for i in range(len(src_times) - 1)]
            flow['src_iat_min'] = min(src_iats) * 1000
            flow['src_iat_max'] = max(src_iats) * 1000
            flow['src_iat_avg'] = sum(src_iats) / len(src_iats) * 1000
            flow['src_iat_std'] = self.std_dev(src_iats) * 1000

        if len(dst_times) > 1:
            dst_iats = [dst_times[i + 1] - dst_times[i] for i in range(len(dst_times) - 1)]
            flow['dst_iat_min'] = min(dst_iats) * 1000
            flow['dst_iat_max'] = max(dst_iats) * 1000
            flow['dst_iat_avg'] = sum(dst_iats) / len(dst_iats) * 1000
            flow['dst_iat_std'] = self.std_dev(dst_iats) * 1000

    @staticmethod
    def std_dev(values: List[float]) -> float:
        """Calculate standard deviation."""
        if not values:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    @staticmethod
    def flags_to_int(flags_set: Set[int]) -> int:
        """Convert TCP flags set to integer."""
        result = 0
        for flag in flags_set:
            result |= flag
        return result

    @staticmethod
    def detect_l7_proto(flow: Dict) -> int:
        """Detect Layer 7 protocol."""
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)

        if src_port == 80 or dst_port == 80:
            return 7  # HTTP
        elif src_port == 443 or dst_port == 443:
            return 91  # HTTPS
        elif src_port == 53 or dst_port == 53:
            return 5  # DNS
        elif src_port == 21 or dst_port == 21:
            return 1  # FTP
        return 0


def process_file(filepath: str, output_csv: str) -> None:
    """Process single PCAP file (supports .pcap, .gz, .zip)."""
    print(f"Processing: {filepath}")

    parser = PCAPParser()
    temp_file = None

    try:
        if filepath.endswith('.gz'):
            temp_file_obj = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
            temp_file = temp_file_obj.name
            temp_file_obj.close()

            with gzip.open(filepath, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    f_out.write(f_in.read())
            parser.parse_pcap_file(temp_file)

        elif filepath.endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                for name in zip_ref.namelist():
                    if name.endswith('.pcap') or name.endswith('.cap'):
                        temp_dir = tempfile.mkdtemp()
                        temp_path = os.path.join(temp_dir, os.path.basename(name))
                        with zip_ref.open(name) as source:
                            with open(temp_path, 'wb') as target:
                                target.write(source.read())
                        parser.parse_pcap_file(temp_path)
                        os.remove(temp_path)
                        os.rmdir(temp_dir)
        else:
            parser.parse_pcap_file(filepath)

        features = parser.calculate_features()

        if features:
            write_csv(features, output_csv)
            print(f"  → {len(features)} flows extracted")
        else:
            print("  → No flows found")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)


def write_csv(features_list: List[Dict[str, Any]], output_file: str) -> None:
    """Write features to CSV file."""
    if not features_list:
        return

    file_exists = os.path.exists(output_file)

    with open(output_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=features_list[0].keys())

        if not file_exists:
            writer.writeheader()

        writer.writerows(features_list)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python pcap_extractor.py <pcap_file(s)> [output.csv]")
        print("\nExamples:")
        print("  python pcap_extractor.py traffic.pcap.gz")
        print("  python pcap_extractor.py *.pcap.gz output.csv")
        sys.exit(1)

    output_csv = 'features.csv'
    input_files = sys.argv[1:]

    if len(sys.argv) > 2 and sys.argv[-1].endswith('.csv'):
        output_csv = sys.argv[-1]
        input_files = sys.argv[1:-1]

    if os.path.exists(output_csv):
        os.remove(output_csv)
        print(f"Removed existing {output_csv}\n")

    all_files = []
    for pattern in input_files:
        all_files.extend(glob.glob(pattern))

    if not all_files:
        print("No files found!")
        sys.exit(1)

    print(f"Processing {len(all_files)} file(s)...\n")

    for filepath in all_files:
        process_file(filepath, output_csv)

    print(f"\nCompleted! Features saved to {output_csv}")


if __name__ == '__main__':
    main()