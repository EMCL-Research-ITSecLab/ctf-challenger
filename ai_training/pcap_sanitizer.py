#!/usr/bin/env python3
"""
Network traffic sanitizer for PCAP files.
Removes traffic involving specified IP addresses with graph-based spidering.
Supports .pcap, .gz, and .zip formats with bidirectional flow analysis.
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
from collections import deque, defaultdict
from typing import Dict, Set, List, Tuple, Optional, Any


class PCAPSanitizer:
    def __init__(self, seed_ips: Set[str], max_depth: int = -1,
                 allowed_networks: Optional[List[str]] = None):
        self.seed_ips = seed_ips
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
                # Read PCAP header
                magic = struct.unpack('I', f.read(4))[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP format: {filepath}")
                    return

                f.read(20)  # Skip rest of global header

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

            # Build bidirectional adjacency
            self.adjacency[src_ip].add(dst_ip)
            self.adjacency[dst_ip].add(src_ip)
            self.stats['flows_analyzed'] += 1

        except Exception:
            pass

    def compute_removal_set(self) -> None:
        """Compute set of IPs to remove using BFS from seed IPs."""
        print("\n" + "=" * 80)
        print("COMPUTING REMOVAL SET")
        print("=" * 80)
        print(f"Seed IPs: {len(self.seed_ips)}")
        print(f"Max depth: {'unlimited' if self.max_depth < 0 else self.max_depth}")

        # Initialize BFS queue with seed IPs
        queue = deque()
        visited: Set[str] = set()
        depth: Dict[str, int] = {}

        # Add seeds and their immediate neighbors within allowed networks
        for seed in self.seed_ips:
            if self._ip_in_allowed(seed):
                if seed not in visited:
                    visited.add(seed)
                    depth[seed] = 0
                    queue.append(seed)
            else:
                # Seed outside allowed network, add its neighbors
                for neighbor in self.adjacency.get(seed, set()):
                    if self._ip_in_allowed(neighbor) and neighbor not in visited:
                        visited.add(neighbor)
                        depth[neighbor] = 0
                        queue.append(neighbor)

        # BFS traversal
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
                      dry_run: bool = False) -> Dict[str, Any]:
        """Second pass: Write sanitized PCAP file."""
        print("\n" + "=" * 80)
        print(f"SANITIZING: {input_path}")
        print("=" * 80)

        if dry_run:
            print("DRY RUN MODE - No output will be written")

        result = {
            'input': input_path,
            'output': output_path if not dry_run else None,
            'packets_read': 0,
            'packets_removed': 0,
            'packets_kept': 0
        }

        try:
            temp_input = None
            temp_output = None

            # Handle compressed input
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

            # Setup output
            if not dry_run:
                if output_path.endswith('.gz'):
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                        temp_output = tmp.name
                    actual_output = temp_output
                else:
                    actual_output = output_path

            with open(input_path, 'rb', buffering=1024 * 1024) as f_in:
                # Read and write PCAP header
                magic = struct.unpack('I', f_in.read(4))[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    print(f"Invalid PCAP format")
                    return result

                # Read rest of header
                f_in.seek(0)
                global_header = f_in.read(24)

                if not dry_run:
                    f_out = open(actual_output, 'wb', buffering=1024 * 1024)
                    f_out.write(global_header)

                # Process packets
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

                    # Check if packet should be removed
                    if self._should_remove_packet(packet_data):
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

            # Handle compressed output
            if not dry_run and output_path.endswith('.gz'):
                with open(temp_output, 'rb') as f_in:
                    with gzip.open(output_path, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(1024 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                os.remove(temp_output)

            # Cleanup temp files
            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)

        except Exception as e:
            print(f"Error sanitizing {input_path}: {e}")
            import traceback
            traceback.print_exc()

        return result

    def _should_remove_packet(self, data: bytes) -> bool:
        """Check if packet involves any IP in removal set."""
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

            return src_ip in self.removal_set or dst_ip in self.removal_set

        except Exception:
            return False

    def print_stats(self) -> None:
        """Print final statistics."""
        total_time = time.time() - self.stats['processing_start']
        print("\n" + "=" * 80)
        print("SANITIZATION STATISTICS")
        print("=" * 80)
        print(f"Total processing time:      {total_time:.2f}s")
        print(f"Seed IPs:                   {len(self.seed_ips)}")
        print(f"Endpoints removed:          {self.stats['endpoints_removed']:,}")
        print(f"Allowed networks:           {len(self.allowed_networks)}")
        for net in self.allowed_networks:
            print(f"  - {net}")
        print("=" * 80)


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
                    # Write global header from first file
                    global_header = f_in.read(24)
                    f_out.write(global_header)
                    first = False
                else:
                    # Skip global header for subsequent files
                    f_in.read(24)

                # Copy packet data
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
        print("\nOptions:")
        print("  --ips <ip,ip,...>         Comma-separated seed IPs to remove")
        print("  --ips-file <file>         File with one IP per line")
        print("  --out-dir <dir>           Output directory (default: current dir)")
        print("  --suffix <suffix>         Output filename suffix (default: _cleaned)")
        print("  --max-depth <n>           Max spider depth, -1=unlimited (default: -1)")
        print("  --allowed-network <cidr>  CIDR to constrain spidering (default: 10.128.0.0/9)")
        print("  --per-file                Build separate graph per file")
        print("  --merge-output <file>     Merge all outputs into single file")
        print("  --dry-run                 Don't write output, show what would be removed")
        print("  --force                   Overwrite existing files without prompting")
        print("  --report <file>           Write JSON report")
        print("\nExamples:")
        print("  python pcap_sanitizer.py --ips 192.168.1.100 traffic.pcap")
        print("  python pcap_sanitizer.py --ips-file bad_ips.txt *.pcap.gz")
        print("  python pcap_sanitizer.py --ips 10.0.0.1,10.0.0.2 --max-depth 2 file.pcap")
        sys.exit(1)

    # Parse arguments
    input_files = []
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

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--ips' and i + 1 < len(sys.argv):
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
        else:
            input_files.append(arg)
            i += 1

    # Load seed IPs
    if not ips_str and not ips_file:
        print("Error: Must provide --ips or --ips-file")
        sys.exit(1)

    seed_ips = load_seed_ips(ips_str, ips_file)
    if not seed_ips:
        print("Error: No seed IPs provided")
        sys.exit(1)

    # Expand input files
    all_files = []
    for pattern in input_files:
        all_files.extend(glob.glob(pattern))

    if not all_files:
        print("Error: No input files found")
        sys.exit(1)

    # Prepare output paths
    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    for inp in all_files:
        base = os.path.basename(inp)
        name = os.path.splitext(base)[0]
        if name.endswith('.pcap'):
            name = name[:-5]
        ext = '.pcap.gz' if inp.endswith('.gz') else '.pcap'
        out_name = name + suffix + ext
        out_path = os.path.join(out_dir, out_name)
        outputs.append((inp, out_path))

    # Check for existing files
    if not force and not dry_run:
        existing = [o for (_, o) in outputs if os.path.exists(o)]
        if existing:
            print("The following files exist:")
            for e in existing:
                print(f"  {e}")
            response = input("Overwrite? [y/N]: ")
            if response.strip().lower() not in ('y', 'yes'):
                print("Aborted")
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
    print("=" * 80)

    start_time = time.time()
    results = []

    if per_file:
        # Process each file independently
        for inp, outp in outputs:
            sanitizer = PCAPSanitizer(seed_ips, max_depth, [allowed_network])
            sanitizer.build_communication_graph([inp])
            sanitizer.compute_removal_set()
            result = sanitizer.sanitize_pcap(inp, outp, dry_run)
            results.append(result)
            sanitizer.print_stats()
    else:
        # Build global graph
        sanitizer = PCAPSanitizer(seed_ips, max_depth, [allowed_network])
        sanitizer.build_communication_graph(all_files)
        sanitizer.compute_removal_set()

        # Sanitize each file
        for inp, outp in outputs:
            result = sanitizer.sanitize_pcap(inp, outp, dry_run)
            results.append(result)

        sanitizer.print_stats()

    # Merge if requested
    if merge_output and not dry_run:
        cleaned_files = [o for (_, o) in outputs]
        merge_pcaps(merge_output, cleaned_files, force)

    total_time = time.time() - start_time

    # Generate report
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

    print("\n" + "=" * 80)
    print("COMPLETED!")
    print("=" * 80)
    print(f"Total time: {total_time:.2f}s")
    print(f"Files processed: {len(results)}")


if __name__ == '__main__':
    main()