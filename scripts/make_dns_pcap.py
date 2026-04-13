#!/usr/bin/env python3
# type: ignore
"""
DNS PCAP Generator — Create realistic DNS traffic captures for testing.

Generates PCAP files from real DNS resolution with support for:
  - Multiple domains (batch mode)
  - Multiple record types per domain (A, AAAA, MX, TXT, NS, CNAME, SOA, HTTPS)
  - DNS-over-TCP simulation
  - Randomized client IPs for multi-source traffic
  - Configurable timing jitter for realistic packet spacing
  - NXDOMAIN simulation for testing threat detection
  - Traffic profile presets (normal, suspicious, mixed)
"""

import argparse
import csv
import ipaddress
import json
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULT_CLIENT_IPV4 = "192.168.1.25"
DEFAULT_CLIENT_IPV6 = "2001:db8::25"
DEFAULT_RESOLVER_IPV4 = "1.1.1.1"
DEFAULT_RESOLVER_IPV6 = "2606:4700:4700::1111"

# Domains for traffic profile presets
NORMAL_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "youtube.com", "microsoft.com", "amazon.com", "reddit.com",
    "cloudflare.com", "python.org",
]

SUSPICIOUS_DOMAINS = [
    "xn--80ak6aa92e.com",  # Punycode domain
    "free-gift-cards-now.tk",
    "login-verify-account.ml",
    "update-your-security.ga",
    "c2-server-callback.xyz",
    "a1b2c3d4e5f6g7h8.top",  # DGA-like
    "data-exfiltration-test.cf",
    "phishing-simulation.buzz",
]

RECORD_TYPES_TO_QUERY = ["A", "AAAA", "MX", "TXT", "NS"]


# ── Utility Functions ────────────────────────────────────────────────────────

def normalize_target(value: str) -> str:
    """Extract a clean domain name from a URL or raw input."""
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""

    if not candidate:
        raise ValueError("Please provide a valid domain or URL.")

    return candidate.rstrip(".")


def resolve_addresses(domain: str) -> Tuple[List[str], List[str]]:
    """Resolve a domain to its IPv4 and IPv6 addresses."""
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()

    try:
        for result in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM):
            family = result[0]
            address = str(result[4][0])
            if family == socket.AF_INET:
                ipv4.add(address)
            elif family == socket.AF_INET6:
                ipv6.add(address)
    except socket.gaierror:
        pass

    return sorted(ipv4), sorted(ipv6)


def random_client_ipv4(base: str = "192.168.1") -> str:
    """Generate a random client IPv4 address within a /24 subnet."""
    return f"{base}.{random.randint(2, 254)}"


def random_client_ipv6(prefix: str = "2001:db8::") -> str:
    """Generate a random client IPv6 address."""
    suffix = random.randint(1, 0xFFFF)
    return f"{prefix}{suffix:x}"


# ── Metadata Export ────────────────────────────────────────────────────────────

def export_packet_metadata(packets: List[Any], csv_path: Optional[Path], json_path: Optional[Path]) -> None:
    """Extract metadata from generated packets and save it as JSON or CSV."""
    if not csv_path and not json_path:
        return

    from scapy.layers.dns import DNS  # pyre-ignore
    from scapy.layers.inet import IP, TCP  # pyre-ignore
    from scapy.layers.inet6 import IPv6  # pyre-ignore
    from datetime import datetime, timezone

    events = []
    for p in packets:
        if not p.haslayer(DNS):
            continue
        
        ip_layer = p[IP] if p.haslayer(IP) else p[IPv6]
        dns = p[DNS]
        transport = "TCP" if p.haslayer(TCP) else "UDP"
        
        qname = dns.qd.qname.decode('utf-8').rstrip('.') if dns.qd else ""
        qtype_int = dns.qd.qtype if dns.qd else 0
        qtype_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS", 5: "CNAME", 6: "SOA", 65: "HTTPS"}
        qtype_name = qtype_map.get(qtype_int, str(qtype_int))

        ts_float = float(getattr(p, "time", 0))
        iso_time = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else ""

        event = {
            "timestamp": ts_float,
            "iso_time": iso_time,
            "source_ip": ip_layer.src,
            "dest_ip": ip_layer.dst,
            "transport": transport,
            "packet_length": len(p),
            "dns_id": dns.id,
            "is_response": bool(dns.qr),
            "domain": qname,
            "qtype": qtype_name,
            "rcode": dns.rcode,
            "answers": [],
            "ttls": []
        }
        
        if dns.qr == 1 and dns.ancount > 0 and hasattr(dns, "an"):
            answers = []
            ttls = []
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if hasattr(rr, 'ttl'):
                        ttls.append(rr.ttl)
                    if hasattr(rr, 'rdata'):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode('utf-8', errors='ignore')
                        elif isinstance(rdata, list):
                            rdata = " ".join(r.decode('utf-8', errors='ignore') if isinstance(r, bytes) else str(r) for r in rdata)
                        answers.append(str(rdata))
                except Exception:
                    pass
            event["answers"] = answers
            event["ttls"] = ttls
            
        events.append(event)
        
    if json_path is not None:
        report_payload = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "packet_count": len(packets),
                "dns_event_count": len(events)
            },
            "events": events
        }
        with open(str(json_path), 'w', encoding='utf-8') as f:
            json.dump(report_payload, f, indent=2)
            
    if csv_path is not None:
        with open(str(csv_path), 'w', encoding='utf-8', newline='') as f:
            if events:
                writer = csv.DictWriter(f, fieldnames=[
                    "iso_time", "timestamp", "source_ip", "dest_ip", "transport", "packet_length", "dns_id", 
                    "is_response", "domain", "qtype", "rcode", "answers", "ttls"
                ])
                writer.writeheader()
                for e in events:
                    row = e.copy()
                    answers_val = e["answers"]
                    row["answers"] = ", ".join(str(a) for a in answers_val) if isinstance(answers_val, list) else str(answers_val)
                    ttls_val = e.get("ttls", [])
                    row["ttls"] = ", ".join(str(t) for t in ttls_val) if isinstance(ttls_val, list) else str(ttls_val)
                    writer.writerow(row)

# ── Packet Builders ──────────────────────────────────────────────────────────

def build_query_packet(
    domain: str,
    qtype: str,
    client_ip: str,
    resolver_ip: str,
    dns_id: int,
    client_port: int,
    use_tcp: bool = False,
    timestamp: Optional[float] = None,
):
    """Build a DNS query packet (UDP or TCP)."""
    from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP  # type: ignore[import]

    dns_payload = DNS(id=dns_id, rd=1, qr=0, qd=DNSQR(qname=domain, qtype=qtype))

    if ipaddress.ip_address(client_ip).version == 4:
        ip_layer = IP(src=client_ip, dst=resolver_ip)
    else:
        ip_layer = IPv6(src=client_ip, dst=resolver_ip)

    if use_tcp:
        transport_layer = TCP(sport=client_port, dport=53, flags="PA", seq=1000, ack=1000)
        # TCP DNS requires a 2-byte length prefix
        dns_bytes = bytes(dns_payload)
        tcp_dns = struct.pack("!H", len(dns_bytes)) + dns_bytes
        packet = Ether() / ip_layer / transport_layer / tcp_dns
    else:
        packet = Ether() / ip_layer / UDP(sport=client_port, dport=53) / dns_payload

    if timestamp is not None:
        packet.time = timestamp

    return packet


def build_response_packet(
    domain: str,
    qtype: str,
    client_ip: str,
    resolver_ip: str,
    answers: List[str],
    dns_id: int,
    client_port: int,
    rcode: int = 0,
    ttl: int = 300,
    use_tcp: bool = False,
    timestamp: Optional[float] = None,
):
    """Build a DNS response packet with answer records."""
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, TCP, UDP  # type: ignore[import]

    answer_chain = None
    for value in answers:
        rr = DNSRR(rrname=domain, type=qtype, ttl=ttl, rdata=value)
        answer_chain = rr if answer_chain is None else answer_chain / rr

    answer_count = len(answers)
    dns_payload = DNS(
        id=dns_id, qr=1, aa=0, ra=1, rd=1, rcode=rcode,
        qd=DNSQR(qname=domain, qtype=qtype),
        an=answer_chain, ancount=answer_count,
    )

    if ipaddress.ip_address(client_ip).version == 4:
        ip_layer = IP(src=resolver_ip, dst=client_ip)
    else:
        ip_layer = IPv6(src=resolver_ip, dst=client_ip)

    if use_tcp:
        transport_layer = TCP(sport=53, dport=client_port, flags="PA", seq=1000, ack=1000)
        dns_bytes = bytes(dns_payload)
        tcp_dns = struct.pack("!H", len(dns_bytes)) + dns_bytes
        packet = Ether() / ip_layer / transport_layer / tcp_dns
    else:
        packet = Ether() / ip_layer / UDP(sport=53, dport=client_port) / dns_payload

    if timestamp is not None:
        packet.time = timestamp

    return packet


def build_nxdomain_packet(
    domain: str,
    qtype: str,
    client_ip: str,
    resolver_ip: str,
    dns_id: int,
    client_port: int,
    timestamp: Optional[float] = None,
):
    """Build an NXDOMAIN response packet."""
    from scapy.all import DNS, DNSQR, Ether, IP, IPv6, UDP  # type: ignore[import]

    dns_payload = DNS(
        id=dns_id, qr=1, aa=0, ra=1, rd=1, rcode=3,  # NXDOMAIN
        qd=DNSQR(qname=domain, qtype=qtype), ancount=0,
    )

    if ipaddress.ip_address(client_ip).version == 4:
        ip_layer = IP(src=resolver_ip, dst=client_ip)
    else:
        ip_layer = IPv6(src=resolver_ip, dst=client_ip)

    packet = Ether() / ip_layer / UDP(sport=53, dport=client_port) / dns_payload

    if timestamp is not None:
        packet.time = timestamp

    return packet


# ── PCAP Generators ──────────────────────────────────────────────────────────

def create_single_domain_pcap(
    domain: str,
    output_path: Path,
    client_ipv4: str,
    client_ipv6: str,
    resolver_ipv4: str,
    resolver_ipv6: str,
    record_types: Optional[List[str]] = None,
    include_tcp: bool = False,
) -> Tuple[int, List[str], List[str], List[Any]]:
    """Create a PCAP for a single domain with multiple record types."""
    from scapy.all import wrpcap  # pyre-ignore

    ipv4_answers, ipv6_answers = resolve_addresses(domain)
    if not ipv4_answers and not ipv6_answers:
        raise RuntimeError(f"No DNS answers were returned for {domain}.")

    packets = []
    base_time = time.time()
    qtypes = record_types or ["A", "AAAA"]

    for idx, qtype in enumerate(qtypes):
        ts = base_time + (idx * random.uniform(0.01, 0.1))

        if qtype == "A" and ipv4_answers:
            dns_id = random.randint(1, 65535)
            client_port = random.randint(20000, 65000)
            packets.append(build_query_packet(domain, qtype, client_ipv4, resolver_ipv4, dns_id, client_port, timestamp=ts))
            packets.append(build_response_packet(domain, qtype, client_ipv4, resolver_ipv4, ipv4_answers, dns_id, client_port, timestamp=ts + 0.003))

            # Also generate TCP variant if requested
            if include_tcp:
                dns_id = random.randint(1, 65535)
                client_port = random.randint(20000, 65000)
                packets.append(build_query_packet(domain, qtype, client_ipv4, resolver_ipv4, dns_id, client_port, use_tcp=True, timestamp=ts + 0.01))
                packets.append(build_response_packet(domain, qtype, client_ipv4, resolver_ipv4, ipv4_answers, dns_id, client_port, use_tcp=True, timestamp=ts + 0.015))

        elif qtype == "AAAA" and ipv6_answers:
            dns_id = random.randint(1, 65535)
            client_port = random.randint(20000, 65000)
            packets.append(build_query_packet(domain, qtype, client_ipv6, resolver_ipv6, dns_id, client_port, timestamp=ts))
            packets.append(build_response_packet(domain, qtype, client_ipv6, resolver_ipv6, ipv6_answers, dns_id, client_port, timestamp=ts + 0.005))

        elif qtype in ("MX", "TXT", "NS", "CNAME", "SOA") and ipv4_answers:
            # Simulate with the domain's IPv4 for these record types
            dns_id = random.randint(1, 65535)
            client_port = random.randint(20000, 65000)
            packets.append(build_query_packet(domain, qtype, client_ipv4, resolver_ipv4, dns_id, client_port, timestamp=ts))
            # Simulate an answer (using the domain itself or the IP)
            simulated_answers = [f"mail.{domain}"] if qtype == "MX" else [domain]
            packets.append(build_response_packet(domain, qtype, client_ipv4, resolver_ipv4, simulated_answers, dns_id, client_port, ttl=random.choice([60, 300, 600, 3600]), timestamp=ts + 0.004))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return len(packets), ipv4_answers, ipv6_answers, packets


@dataclass
class PcapStats:
    domains: int = 0
    packets: int = 0
    nxdomains: int = 0
    tcp_queries: int = 0
    errors: List[str] = field(default_factory=list)

def create_batch_pcap(
    domains: List[str],
    output_path: Path,
    resolver_ipv4: str,
    resolver_ipv6: str,
    record_types: Optional[List[str]] = None,
    include_nxdomain: bool = False,
    include_tcp: bool = False,
    randomize_clients: bool = True,
) -> Tuple[Dict[str, Any], List[Any]]:
    """Create a PCAP with traffic from multiple domains and clients."""
    from scapy.all import wrpcap  # pyre-ignore

    packets = []
    stats = PcapStats()
    base_time = time.time()
    qtypes = record_types or ["A", "AAAA"]

    for domain_idx, domain in enumerate(domains):
        ts = base_time + (domain_idx * random.uniform(0.05, 0.3))

        if randomize_clients:
            client_v4 = random_client_ipv4()
            client_v6 = random_client_ipv6()
        else:
            client_v4 = DEFAULT_CLIENT_IPV4
            client_v6 = DEFAULT_CLIENT_IPV6

        try:
            ipv4_answers, ipv6_answers = resolve_addresses(domain)
        except Exception:
            ipv4_answers, ipv6_answers = [], []

        if not ipv4_answers and not ipv6_answers:
            if include_nxdomain:
                # Generate NXDOMAIN response
                dns_id = random.randint(1, 65535)
                client_port = random.randint(20000, 65000)
                packets.append(build_query_packet(domain, "A", client_v4, resolver_ipv4, dns_id, client_port, timestamp=ts))
                packets.append(build_nxdomain_packet(domain, "A", client_v4, resolver_ipv4, dns_id, client_port, timestamp=ts + 0.002))
                stats.nxdomains += 1
                stats.domains += 1
            else:
                stats.errors.append(f"No answers for {domain}")
            continue

        stats.domains += 1

        for qtype_idx, qtype in enumerate(qtypes):
            query_ts = ts + (qtype_idx * random.uniform(0.01, 0.05))
            dns_id = random.randint(1, 65535)
            client_port = random.randint(20000, 65000)

            if qtype == "A" and ipv4_answers:
                packets.append(build_query_packet(domain, qtype, client_v4, resolver_ipv4, dns_id, client_port, timestamp=query_ts))
                packets.append(build_response_packet(domain, qtype, client_v4, resolver_ipv4, ipv4_answers, dns_id, client_port, ttl=random.choice([60, 300, 600, 3600]), timestamp=query_ts + random.uniform(0.002, 0.02)))
            elif qtype == "AAAA" and ipv6_answers:
                packets.append(build_query_packet(domain, qtype, client_v6, resolver_ipv6, dns_id, client_port, timestamp=query_ts))
                packets.append(build_response_packet(domain, qtype, client_v6, resolver_ipv6, ipv6_answers, dns_id, client_port, ttl=random.choice([60, 300, 600]), timestamp=query_ts + random.uniform(0.003, 0.025)))

            # TCP variant
            if include_tcp and qtype == "A" and ipv4_answers and random.random() < 0.3:
                tcp_ts = query_ts + 0.05
                dns_id = random.randint(1, 65535)
                client_port = random.randint(20000, 65000)
                packets.append(build_query_packet(domain, qtype, client_v4, resolver_ipv4, dns_id, client_port, use_tcp=True, timestamp=tcp_ts))
                packets.append(build_response_packet(domain, qtype, client_v4, resolver_ipv4, ipv4_answers, dns_id, client_port, use_tcp=True, timestamp=tcp_ts + 0.004))
                stats.tcp_queries += 1

    # Sort by timestamp for realistic ordering
    packets.sort(key=lambda p: float(getattr(p, "time", 0)))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    stats.packets = len(packets)
    return {
        "domains": stats.domains,
        "packets": stats.packets,
        "nxdomains": stats.nxdomains,
        "tcp_queries": stats.tcp_queries,
        "errors": stats.errors,
    }, packets


# ── Traffic Profiles ─────────────────────────────────────────────────────────

def generate_profile_pcap(profile: str, output_path: Path, resolver_ipv4: str, resolver_ipv6: str) -> Tuple[Dict[str, Any], List[Any]]:
    """Generate PCAP from a traffic profile preset."""
    if profile == "normal":
        domains = NORMAL_DOMAINS
        return create_batch_pcap(
            domains, output_path, resolver_ipv4, resolver_ipv6,
            record_types=["A", "AAAA"],
            include_nxdomain=False, include_tcp=False, randomize_clients=True,
        )
    elif profile == "suspicious":
        domains = SUSPICIOUS_DOMAINS
        return create_batch_pcap(
            domains, output_path, resolver_ipv4, resolver_ipv6,
            record_types=["A", "AAAA", "TXT"],
            include_nxdomain=True, include_tcp=True, randomize_clients=True,
        )
    elif profile == "mixed":
        domains = NORMAL_DOMAINS + SUSPICIOUS_DOMAINS
        random.shuffle(domains)
        return create_batch_pcap(
            domains, output_path, resolver_ipv4, resolver_ipv6,
            record_types=["A", "AAAA", "MX", "TXT"],
            include_nxdomain=True, include_tcp=True, randomize_clients=True,
        )
    else:
        raise ValueError(f"Unknown profile: {profile}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create realistic DNS PCAP files for testing the DNS Sinkhole Console.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s google.com                                   # Single domain, A + AAAA
  %(prog)s google.com github.com python.org             # Multiple domains
  %(prog)s --profile normal                             # Normal traffic profile (10 domains)
  %(prog)s --profile suspicious                         # Suspicious traffic for threat testing
  %(prog)s --profile mixed --include-tcp --nxdomain     # Full mixed traffic simulation
  %(prog)s google.com --types A AAAA MX TXT --tcp       # Specific record types with TCP
        """,
    )
    parser.add_argument("targets", nargs="*", help="Domains or URLs to resolve")
    parser.add_argument("--output", "-o", default="dns-capture.pcap", help="Output PCAP path (default: dns-capture.pcap)")
    parser.add_argument("--csv", help="Export packet metadata to CSV format (specify path)")
    parser.add_argument("--json", help="Export packet metadata to JSON format (specify path)")
    parser.add_argument("--profile", choices=["normal", "suspicious", "mixed"],
                        help="Use a traffic profile preset instead of specific targets")
    parser.add_argument("--types", nargs="+", default=["A", "AAAA"],
                        help="Record types to query (default: A AAAA)")
    parser.add_argument("--tcp", action="store_true", help="Include DNS-over-TCP queries")
    parser.add_argument("--nxdomain", action="store_true", help="Include NXDOMAIN responses for unresolvable domains")
    parser.add_argument("--randomize-clients", action="store_true", default=True,
                        help="Use random client IPs for each domain (default: true)")
    parser.add_argument("--client-ipv4", default=DEFAULT_CLIENT_IPV4)
    parser.add_argument("--client-ipv6", default=DEFAULT_CLIENT_IPV6)
    parser.add_argument("--resolver-ipv4", default=DEFAULT_RESOLVER_IPV4)
    parser.add_argument("--resolver-ipv6", default=DEFAULT_RESOLVER_IPV6)
    args = parser.parse_args()

    output_path = Path(args.output).expanduser().resolve()

    # ── Profile mode ──
    if args.profile:
        print(f"Generating '{args.profile}' traffic profile...")
        stats: Dict[str, Any] = {}
        try:
            stats, packets = generate_profile_pcap(args.profile, output_path, args.resolver_ipv4, args.resolver_ipv6)
            export_packet_metadata(packets, Path(args.csv) if args.csv else None, Path(args.json) if args.json else None)
        except Exception as exc:
            print(f"Failed to create PCAP: {exc}")
            return 1

        print(f"\n  Created: {output_path}")
        if args.csv: print(f"  CSV:     {args.csv}")
        if args.json: print(f"  JSON:    {args.json}")
        print(f"  Profile: {args.profile}")
        print(f"  Domains: {stats['domains']}")
        print(f"  Packets: {stats['packets']}")
        if stats.get("nxdomains"):
            print(f"  NXDOMAIN: {stats['nxdomains']}")
        if stats.get("tcp_queries"):
            print(f"  TCP queries: {stats['tcp_queries']}")
        if stats.get("errors"):
            print(f"  Skipped: {len(stats['errors'])} domains (no resolution)")
        return 0

    # ── Target mode ──
    if not args.targets:
        parser.error("Provide at least one domain/URL or use --profile.")

    targets = [normalize_target(t) for t in args.targets]

    if len(targets) == 1:
        # Single domain mode
        domain = targets[0]
        print(f"Resolving {domain}...")
        try:
            packet_count, ipv4_answers, ipv6_answers, packets = create_single_domain_pcap(
                domain=domain,
                output_path=output_path,
                client_ipv4=args.client_ipv4,
                client_ipv6=args.client_ipv6,
                resolver_ipv4=args.resolver_ipv4,
                resolver_ipv6=args.resolver_ipv6,
                record_types=args.types,
                include_tcp=args.tcp,
            )
            export_packet_metadata(packets, Path(args.csv) if args.csv else None, Path(args.json) if args.json else None)
        except socket.gaierror as exc:
            print(f"DNS resolution failed: {exc}")
            return 1
        except Exception as exc:
            print(f"Failed to create PCAP: {exc}")
            return 1

        print(f"\n  Created: {output_path}")
        if args.csv: print(f"  CSV:     {args.csv}")
        if args.json: print(f"  JSON:    {args.json}")
        print(f"  Target: {domain}")
        print(f"  Packets: {packet_count}")
        print(f"  Types: {', '.join(args.types)}")
        if ipv4_answers:
            print(f"  A records: {', '.join(ipv4_answers)}")
        if ipv6_answers:
            print(f"  AAAA records: {', '.join(ipv6_answers)}")
    else:
        # Batch mode
        print(f"Resolving {len(targets)} domains...")
        try:
            stats, packets = create_batch_pcap(
                domains=targets,
                output_path=output_path,
                resolver_ipv4=args.resolver_ipv4,
                resolver_ipv6=args.resolver_ipv6,
                record_types=args.types,
                include_nxdomain=args.nxdomain,
                include_tcp=args.tcp,
                randomize_clients=args.randomize_clients,
            )
            export_packet_metadata(packets, Path(args.csv) if args.csv else None, Path(args.json) if args.json else None)
        except Exception as exc:
            print(f"Failed to create PCAP: {exc}")
            return 1

        print(f"\n  Created: {output_path}")
        if args.csv: print(f"  CSV:     {args.csv}")
        if args.json: print(f"  JSON:    {args.json}")
        print(f"  Domains: {stats['domains']}")
        print(f"  Packets: {stats['packets']}")
        if stats.get("nxdomains"):
            print(f"  NXDOMAIN: {stats['nxdomains']}")
        if stats.get("tcp_queries"):
            print(f"  TCP queries: {stats['tcp_queries']}")
        if stats.get("errors"):
            for err in stats["errors"]:
                print(f"  ⚠ {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
