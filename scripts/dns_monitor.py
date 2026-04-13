#!/usr/bin/env python3
# pylint: disable=import-error
# type: ignore
"""
DNS Monitor — Real-time DNS traffic capture and analysis.

Supports live capture and PCAP file analysis via Scapy or TShark.
Emits structured JSON events to stdout for the Flask frontend to consume via SSE.

Enhanced features:
  - DoH / DoT / DNS-over-QUIC protocol detection
  - DNS response answer parsing (A, AAAA, CNAME, MX, TXT, etc.)
  - TTL extraction from DNS responses
  - NXDOMAIN / SERVFAIL / REFUSED response code detection
  - Threat scoring based on domain entropy, TLD reputation, and query patterns
  - Expanded record type map (48 types)
  - Batch MongoDB inserts for high-throughput captures
  - Graceful shutdown with session statistics summary
"""

import argparse
import json
import math
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Globals ──────────────────────────────────────────────────────────────────

RUNNING = True
MONGO_LOCK = threading.Lock()
MONGO_STATE: Dict[str, Any] = {
    "signature": None,
    "client": None,
    "collection": None,
}
MONGO_BATCH: List[Dict[str, Any]] = []
MONGO_BATCH_SIZE = 25
MONGO_BATCH_LOCK = threading.Lock()
MONGO_LAST_FLUSH = time.time()

SESSION_STATS = Counter()  # domain, record_type, source_ip, transport, rcode

# ── Record Type Map (expanded) ───────────────────────────────────────────────

RECORD_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY",
    28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT",
    39: "DNAME", 41: "OPT", 43: "DS", 44: "SSHFP", 45: "IPSECKEY",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3",
    51: "NSEC3PARAM", 52: "TLSA", 55: "HIP", 59: "CDS", 60: "CDNSKEY",
    61: "OPENPGPKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF",
    249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR",
    255: "ANY", 256: "URI", 257: "CAA", 32768: "TA", 32769: "DLV",
}

# DNS response codes
RCODE_MAP = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

# Suspicious TLDs commonly associated with abuse
SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club",
    "work", "info", "click", "link", "online", "site", "icu",
    "cam", "monster", "rest", "uno", "surf",
})
POPULAR_DOMAINS = frozenset({
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "instagram.com", "twitter.com", "linkedin.com", "netflix.com", "paypal.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "github.com",
})

TLD_WEIGHTS = {
    "tk": 10, "ml": 10, "ga": 10, "cf": 10, "gq": 10, "top": 8, "xyz": 8,
    "buzz": 8, "club": 7, "work": 7, "info": 6, "click": 6, "link": 6,
    "online": 6, "site": 6, "icu": 8, "cam": 8, "monster": 8, "rest": 7,
    "uno": 7, "surf": 7
}

# ── Utility Functions ────────────────────────────────────────────────────────

def emit(payload: Dict[str, Any]) -> None:
    """Write a JSON payload to stdout for the Flask backend to consume."""
    try:
        print(json.dumps(payload), flush=True)
    except BrokenPipeError:
        sys.exit(0)
    except Exception as exc:
        print(f"Error emitting payload: {exc}", file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def epoch_to_iso(value: str) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return now_iso()


def resolve_record_type(value: Any) -> str:
    """Convert a numeric or string DNS record type to its standard name."""
    if value is None:
        return "A"

    if isinstance(value, bytes):
        value = value.decode(errors="ignore")

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return "A"
        if value.isdigit():
            value = int(value)
        else:
            return value.upper()

    if isinstance(value, int):
        return RECORD_TYPE_MAP.get(value, str(value))

    return str(value).upper()


def resolve_rcode(value: Any) -> str:
    """Convert a numeric DNS response code to its standard name."""
    if value is None:
        return "NOERROR"
    try:
        return RCODE_MAP.get(int(value), f"RCODE_{value}")
    except (TypeError, ValueError):
        return str(value).upper()


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

# ── Threat Scoring ───────────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random)."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

def check_typosquatting(domain: str) -> Optional[str]:
    """Check if a domain is a potential typosquatting attempt using Levenshtein distance."""
    domain = domain.lower().rstrip(".")
    if domain in POPULAR_DOMAINS:
        return None
        
    norm_domain = domain.replace("i", "l").replace("1", "l").replace("0", "o")
    
    for popular in POPULAR_DOMAINS:
        norm_pop = popular.replace("i", "l").replace("1", "l").replace("0", "o")
        if norm_domain == norm_pop:
            return popular
            
        if abs(len(domain) - len(popular)) > 2:
            continue
        if levenshtein_distance(domain, popular) == 1:
            return popular
    return None


def score_threat(domain: str, record_type: str, rcode: str, source_ip: str = "unknown") -> Dict[str, Any]:
    """
    Score a DNS event for suspicious characteristics.
    Returns a dict with threat_level (low/medium/high), score (0-100), and reasons.
    """
    score = 0
    reasons = []

    # 1. TLD Analysis
    tld = domain.split(".")[-1].lower() if "." in domain else ""
    tld_score = TLD_WEIGHTS.get(tld, 0)
    if tld_score >= 8:
        score += 35
        reasons.append(f"Suspicious TLD (.{tld})")
    elif tld_score >= 6:
        score += 15
        reasons.append(f"Suboptimal TLD (.{tld})")

    entropy = calculate_entropy(domain)
    # 2. Domain entropy — DGA domains tend to have high entropy
    if entropy > 4.0:
        score += 30
        reasons.append(f"High domain entropy ({entropy:.2f})")
    elif entropy > 3.5:
        score += 15
        reasons.append(f"Elevated domain entropy ({entropy:.2f})")

    # 3. Domain length — unusually long subdomains can signal tunneling
    labels = domain.split(".")
    if len(domain) > 60:
        score += 25
        reasons.append(f"Very long domain name ({len(domain)} chars)")
    elif len(domain) > 40:
        score += 10
        reasons.append(f"Long domain name ({len(domain)} chars)")

    # 4. Numeric-heavy subdomain — common in DGA
    if labels and re.search(r"\d{4,}", labels[0]):
        score += 10
        reasons.append("Numeric-heavy subdomain label")
        
    # 4.1 Consonant sequences — Advanced DGA Heuristic
    if labels:
        main_label = labels[0]
        max_cons = max((len(c) for c in re.split(r'[^bcdfghjklmnpqrstvwxyz]+', main_label)), default=0)
        if max_cons >= 5:
            score += 25
            reasons.append(f"DGA heuristic ({max_cons} consecutive consonants)")

    # 5. Excessive subdomains — DNS tunneling indicator
    if len(labels) > 5:
        score += 15
        reasons.append(f"Excessive subdomain depth ({len(labels)} labels)")

    # 6. Unusual record types
    unusual_types = {"TXT", "NULL", "ANY", "AXFR", "IXFR", "HINFO", "KEY", "SIG"}
    if record_type in unusual_types:
        score += 10
        reasons.append(f"Unusual record type ({record_type})")

    # 7. NXDOMAIN response — can indicate reconnaissance
    if rcode == "NXDOMAIN":
        score += 5
        reasons.append("NXDOMAIN response")
    elif rcode in ("SERVFAIL", "REFUSED"):
        score += 10
        reasons.append(f"Error response ({rcode})")

    # 8. Typosquatting detection
    target = check_typosquatting(domain)
    if target:
        score += 45
        reasons.append(f"Potential typosquatting of {target}")

    return {
        "threatScore": score,
        "threatLevel": "high" if score >= 60 else ("medium" if score >= 30 else "low"),
        "threatReasons": reasons,
    }


# ── Protocol Detection ───────────────────────────────────────────────────────

def detect_protocol(transport: str, destination_port: str) -> str:
    """Detect the DNS protocol variant based on transport and port."""
    port = str(destination_port)

    if transport == "tcp" and port == "853":
        return "DoT"       # DNS over TLS
    if transport == "tcp" and port == "443":
        return "DoH"       # DNS over HTTPS
    if transport == "udp" and port == "443":
        return "DoQ"       # DNS over QUIC (RFC 9250)
    if transport == "tcp" and port == "53":
        return "DNS/TCP"
    return "DNS"


# ── Signal Handling ──────────────────────────────────────────────────────────

def handle_signal(signum: int, frame: Any) -> None:
    del frame
    global RUNNING
    RUNNING = False
    emit({
        "kind": "status",
        "status": "stopping",
        "note": f"Received signal {signum}, shutting down capture.",
    })


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# ── MongoDB ──────────────────────────────────────────────────────────────────

def get_mongo_collection(args: Any) -> Any:
    if not args.mongo_uri:
        return None

    signature = (args.mongo_uri, args.mongo_db, args.mongo_collection)

    with MONGO_LOCK:
        if MONGO_STATE["signature"] == signature and MONGO_STATE["collection"] is not None:
            return MONGO_STATE["collection"]

        try:
            from pymongo import MongoClient
        except ImportError:
            emit({
                "kind": "error",
                "message": "MongoDB persistence requested but pymongo is not installed.",
            })
            return None

        try:
            client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=2000)
            client.admin.command("ping")
            collection = client[args.mongo_db][args.mongo_collection]
        except Exception as exc:
            emit({
                "kind": "error",
                "message": f"MongoDB connection failed: {exc}",
            })
            return None

        MONGO_STATE["signature"] = signature
        MONGO_STATE["client"] = client
        MONGO_STATE["collection"] = collection
        return collection


def persist_event(event: Dict[str, Any], args: Any) -> None:
    """Buffer events and batch-insert into MongoDB for throughput."""
    global MONGO_LAST_FLUSH
    collection = get_mongo_collection(args)
    if collection is None:
        return

    batch_to_insert = None
    with MONGO_BATCH_LOCK:
        MONGO_BATCH.append(event)
        current_time = time.time()
        if len(MONGO_BATCH) >= MONGO_BATCH_SIZE or (current_time - MONGO_LAST_FLUSH) > 5.0:
            batch_to_insert = list(MONGO_BATCH)
            MONGO_BATCH.clear()
            MONGO_LAST_FLUSH = current_time

    if batch_to_insert:
        try:
            collection.insert_many(batch_to_insert, ordered=False)
        except Exception as exc:
            emit({
                "kind": "error",
                "message": f"MongoDB batch insert failed: {exc}",
            })


def flush_mongo_batch(args) -> None:
    """Flush any remaining events in the MongoDB batch buffer."""
    collection = get_mongo_collection(args)
    if collection is None:
        return

    with MONGO_BATCH_LOCK:
        if not MONGO_BATCH:
            return
        batch = list(MONGO_BATCH)
        MONGO_BATCH.clear()

    try:
        collection.insert_many(batch, ordered=False)
    except Exception as exc:
        emit({
            "kind": "error",
            "message": f"MongoDB batch flush failed: {exc}",
        })


# ── Event Builder ────────────────────────────────────────────────────────────

def build_event(
    domain: str,
    source_ip: str,
    destination_ip: str,
    record_type: Any,
    tool: str,
    mode: str,
    transport: str = "udp",
    timestamp: Optional[str] = None,
    destination_port: Optional[Any] = None,
    rcode: Optional[Any] = None,
    ttl: Optional[int] = None,
    answers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a normalized DNS event with protocol detection, threat scoring, and response data."""

    normalized_type = resolve_record_type(record_type)
    normalized_rcode = resolve_rcode(rcode)
    port = str(destination_port or "53")
    protocol = detect_protocol(transport.lower(), port)
    threat = score_threat(domain or "unknown", normalized_type, normalized_rcode, source_ip=source_ip)

    # Track session statistics
    SESSION_STATS[f"domain:{domain or 'unknown'}"] += 1
    SESSION_STATS[f"type:{normalized_type}"] += 1
    SESSION_STATS[f"source:{source_ip or 'unknown'}"] += 1
    SESSION_STATS[f"transport:{transport.lower()}"] += 1
    SESSION_STATS[f"rcode:{normalized_rcode}"] += 1
    SESSION_STATS["total"] += 1

    event = {
        "kind": "event",
        "timestamp": timestamp or now_iso(),
        "domain": domain or "unknown",
        "queryName": domain or "unknown",
        "sourceIp": source_ip or "unknown",
        "destinationIp": destination_ip or "unknown",
        "resolverIp": destination_ip or "unknown",
        "destinationPort": port,
        "recordType": normalized_type,
        "type": normalized_type,
        "protocol": protocol,
        "transport": transport.lower(),
        "rcode": normalized_rcode,
        "tool": tool,
        "mode": mode,
        "confidence": "observed",
        "source": "python-monitor",
    }

    # Optional enrichment fields
    if ttl is not None:
        event["ttl"] = int(ttl)

    if answers:
        event["answers"] = answers[:10]  # Cap at 10 answers to avoid bloat
        event["answerCount"] = len(answers)

    # Threat intelligence
    event.update(threat)

    return event


# ── Session Summary ──────────────────────────────────────────────────────────

def emit_session_summary() -> None:
    """Emit a final session statistics summary at shutdown."""
    total = SESSION_STATS.get("total", 0)
    if total == 0:
        return

    # Build top-N lists
    def top_n(prefix: str, n: int = 5) -> List[Tuple[str, int]]:
        items = [
            (key.split(":", 1)[1], count)
            for key, count in SESSION_STATS.items()
            if key.startswith(prefix)
        ]
        return sorted(items, key=lambda x: -x[1])[:n]

    summary = {
        "kind": "status",
        "status": "completed",
        "note": f"Session complete. Processed {total} DNS queries.",
        "sessionSummary": {
            "totalEvents": total,
            "topDomains": [{"domain": d, "count": c} for d, c in top_n("domain:")],
            "topRecordTypes": [{"type": t, "count": c} for t, c in top_n("type:")],
            "topSourceIps": [{"ip": ip, "count": c} for ip, c in top_n("source:")],
            "topRcodes": [{"rcode": r, "count": c} for r, c in top_n("rcode:")],
            "transportBreakdown": dict(top_n("transport:", 10)),
        },
    }
    emit(summary)


# ── Scapy Capture ────────────────────────────────────────────────────────────

def parse_scapy_packets(args: Any) -> int:
    try:
        from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, PcapReader, TCP, UDP, sniff, send  # type: ignore[import]
    except ImportError as exc:
        emit({
            "kind": "error",
            "message": f"scapy is required for this mode: {exc}",
        })
        return 1

    emit({
        "kind": "status",
        "status": "running",
        "tool": "scapy",
        "note": "Scapy capture started.",
    })

    seen = 0
    last_status_time = time.time()
    stop_capture = False

    def extract_answers(dns_layer: Any) -> Tuple[List[str], Optional[int]]:
        """Extract answer records and minimum TTL from a DNS response."""
        answers = []
        min_ttl = None
        try:
            answer_count = getattr(dns_layer, "ancount", 0) or 0
            if answer_count > 0 and hasattr(dns_layer, "an") and dns_layer.an:
                rr = dns_layer.an
                for _ in range(min(answer_count, 20)):
                    if rr is None:
                        break
                    rdata = getattr(rr, "rdata", None)
                    if rdata:
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="ignore")
                        answers.append(str(rdata))
                    ttl = getattr(rr, "ttl", None)
                    if ttl is not None:
                        if min_ttl is None or ttl < min_ttl:
                            min_ttl = ttl
                    rr = getattr(rr, "payload", None)
                    if rr and not isinstance(rr, DNSRR):
                        break
        except Exception:
            pass
        return answers, min_ttl

    def handle_packet(packet: Any) -> bool:
        nonlocal seen, last_status_time

        if stop_capture or not RUNNING:
            return True

        try:
            if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
                return False

            dns_layer = packet[DNS]
            is_response = getattr(dns_layer, "qr", 0) == 1
            is_query = getattr(dns_layer, "qr", 1) == 0

            # We process both queries and responses, but only emit for queries
            # For responses, we try to match and enrich
            if not is_query and not is_response:
                return False

            question = packet[DNSQR]
            domain = question.qname.decode(errors="ignore").rstrip(".")
            if not domain:
                return False

            source_ip = "unknown"
            destination_ip = "unknown"
            if packet.haslayer(IP):
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst

            transport = "udp"
            destination_port = "53"
            if packet.haslayer(TCP):
                transport = "tcp"
                destination_port = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                transport = "udp"
                destination_port = str(packet[UDP].dport)

            # Extract rcode, answers, TTL from responses
            rcode = None
            answers = []
            ttl = None
            if is_response:
                rcode = getattr(dns_layer, "rcode", 0)
                answers, ttl = extract_answers(dns_layer)
                # Swap source/dest for responses (resolver → client)
                source_ip, destination_ip = destination_ip, source_ip

            event = build_event(
                domain=domain,
                source_ip=source_ip,
                destination_ip=destination_ip,
                record_type=getattr(question, "qtype", "A"),
                tool="scapy",
                mode=args.mode,
                transport=transport,
                timestamp=epoch_to_iso(str(getattr(packet, "time", time.time()))),
                destination_port=destination_port,
                rcode=rcode,
                ttl=ttl,
                answers=answers if answers else None,
            )
            
            # Active DNS Spoofing (Sinkholing)
            if getattr(args, "sinkhole_ip", None) and event.get("threatLevel") == "high" and is_query and transport == "udp":
                try:
                    if packet.haslayer(IP) and packet.haslayer(UDP):
                        spoofed_resp = IP(dst=source_ip, src=destination_ip) / \
                                       UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                       DNS(id=dns_layer.id, qr=1, aa=1, rcode=0, qd=dns_layer.qd,
                                           an=DNSRR(rrname=domain + ".", type="A", ttl=60, rdata=args.sinkhole_ip))
                        send(spoofed_resp, verbose=0, iface=args.interface or None)
                        event["action"] = "sinkholed"
                        event["answers"] = [args.sinkhole_ip]
                except Exception:
                    pass

            emit(event)
            persist_event(event, args)
            seen += 1

            current_time = time.time()
            if seen % 100 == 0 or (current_time - last_status_time) > 5:
                emit({
                    "kind": "status",
                    "status": "running",
                    "tool": "scapy",
                    "note": f"Processed {seen} DNS queries with Scapy.",
                })
                last_status_time = current_time

            return bool(args.limit and seen >= args.limit)
        except Exception as exc:
            emit({
                "kind": "error",
                "message": f"Error processing packet: {exc}",
            })
            return False

    def process_packet(packet: Any) -> None:
        nonlocal stop_capture

        if handle_packet(packet):
            stop_capture = True

    if args.mode == "manual":
        if not args.pcap:
            emit({"kind": "error", "message": "Manual mode requires --pcap."})
            return 1

        try:
            reader = PcapReader(args.pcap)
            for packet in reader:
                if stop_capture or not RUNNING:
                    break
                if handle_packet(packet):
                    stop_capture = True
                    break
            return 0
        except Exception as exc:
            emit({"kind": "error", "message": f"Error reading PCAP file: {exc}"})
            return 1

    try:
        emit({
            "kind": "status",
            "status": "running",
            "tool": "scapy",
            "note": f"Starting live capture on interface {args.interface or 'default'}.",
        })

        # Capture DNS on standard port 53, DoT on 853, and DoH on 443
        bpf_filter = "port 53 or port 853 or port 443"

        sniff(
            iface=args.interface or None,
            filter=bpf_filter,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: stop_capture or not RUNNING,
        )
        return 0
    except Exception as exc:
        emit({"kind": "error", "message": f"Error in live capture: {exc}"})
        return 1


# ── TShark Capture ───────────────────────────────────────────────────────────

def parse_tshark(args: Any) -> int:
    tshark = shutil.which("tshark")
    if not tshark:
        emit({
            "kind": "error",
            "message": "tshark was not found. Install Wireshark/tshark or switch to scapy.",
        })
        return 1

    cmd = [
        tshark, "-l", "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-e", "udp.dstport",
        "-e", "tcp.dstport",
        "-e", "dns.flags.rcode",       # Response code
        "-e", "dns.resp.ttl",          # Response TTL
        "-e", "dns.a",                 # A record answers
        "-e", "dns.aaaa",              # AAAA record answers
        "-e", "dns.cname",             # CNAME answers
        "-e", "dns.mx.mail_exchange",  # MX answers
        "-e", "dns.txt",               # TXT answers
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=a",
        "-E", "aggregator=;",
    ]

    if args.mode == "manual":
        if not args.pcap:
            emit({"kind": "error", "message": "Manual mode requires --pcap."})
            return 1
        cmd.extend(["-r", args.pcap])
    else:
        if args.interface:
            cmd.extend(["-i", args.interface])
        # Capture DNS, DoT, and DoH traffic
        cmd.extend(["-f", "port 53 or port 853 or port 443"])

    emit({
        "kind": "status",
        "status": "running",
        "tool": "tshark",
        "note": "TShark capture started.",
    })

    process = None
    seen = 0
    last_status_time = time.time()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        while RUNNING and process.stdout:
            line = process.stdout.readline()
            if not line:
                break

            parts = line.rstrip().split("|")
            # We now expect 16 fields, including TXT answers.
            while len(parts) < 16:
                parts.append("")

            source_ip = parts[1] or parts[2] or "unknown"
            destination_ip = parts[3] or parts[4] or "unknown"
            domain = parts[5].rstrip(".")
            if not domain:
                continue

            udp_port = parts[7]
            tcp_port = parts[8]
            transport = "tcp" if tcp_port else "udp"
            destination_port = tcp_port or udp_port or "53"

            # Response code and TTL
            rcode = parts[9] if parts[9] else None
            ttl = None
            if parts[10]:
                try:
                    ttl = int(parts[10].split(";")[0])  # Take first TTL
                except (ValueError, IndexError):
                    pass

            # Collect answers from various record types
            answers = []
            for idx in range(11, 16):
                if idx < len(parts) and parts[idx]:
                    answers.extend(answer for answer in parts[idx].split(";") if answer)

            event = build_event(
                domain=domain,
                source_ip=source_ip,
                destination_ip=destination_ip,
                record_type=parts[6] or "A",
                tool="tshark",
                mode=args.mode,
                transport=transport,
                timestamp=epoch_to_iso(parts[0]),
                destination_port=destination_port,
                rcode=rcode,
                ttl=ttl,
                answers=answers if answers else None,
            )
            emit(event)
            persist_event(event, args)
            seen += 1

            current_time = time.time()
            if seen % 100 == 0 or (current_time - last_status_time) > 5:
                emit({
                    "kind": "status",
                    "status": "running",
                    "tool": "tshark",
                    "note": f"Processed {seen} DNS queries with TShark.",
                })
                last_status_time = current_time

            if args.limit and seen >= args.limit:
                break
    except Exception as exc:
        emit({"kind": "error", "message": f"Error in TShark processing: {exc}"})
        return 1
    finally:
        if process:
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            except Exception as exc:
                emit({"kind": "error", "message": f"Error terminating TShark process: {exc}"})

    return 0


# ── TCP Scan ─────────────────────────────────────────────────────────────────

def run_tcp_dns_scan(args: Any) -> int:
    try:
        from scapy.all import IP, TCP, sr  # type: ignore[import]
    except ImportError as exc:
        emit({"kind": "error", "message": f"scapy is required for scan mode: {exc}"})
        return 1

    target = getattr(args, "scan_target", "")
    if not target:
        emit({"kind": "error", "message": "Scan mode requires --scan-target argument."})
        return 1

    emit({
        "kind": "status",
        "status": "starting",
        "tool": "scapy-scanner",
        "note": f"Starting TCP SYN scan for DNS services on {target} (Ports: 53, 443, 853)...",
    })

    ports = [53, 443, 853]
    try:
        ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="S"), timeout=3, verbose=0)
        found_count = 0

        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12: # SYN-ACK
                found_count += 1
                port = s[TCP].dport
                protocol = "DNS/TCP" if port == 53 else ("DoH" if port == 443 else "DoT")
                event = build_event(
                    domain=f"scan-{port}",
                    source_ip=s[IP].src,
                    destination_ip=s[IP].dst,
                    record_type="SCAN",
                    tool="scapy-scanner",
                    mode="scan",
                    transport="tcp",
                    destination_port=str(port),
                    answers=[f"Open {protocol} port"],
                )
                emit(event)
                persist_event(event, args)

        emit({
            "kind": "status",
            "status": "completed",
            "tool": "scapy-scanner",
            "note": f"TCP SYN Scan complete. Found {found_count} open DNS-related ports.",
        })
        return 0
    except Exception as exc:
        emit({"kind": "error", "message": f"TCP Scan failed: {exc}"})
        return 1

# ── Main Entry Point ─────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Real-time DNS monitor with protocol detection, threat scoring, and response analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode live --preferred-tool auto
  %(prog)s --mode manual --pcap /tmp/capture.pcap --preferred-tool scapy
  %(prog)s --mode live --interface eth0 --mongo-uri mongodb://localhost:27017
        """,
    )
    parser.add_argument("--mode", choices=["live", "manual", "scan"], default="live",
                        help="Capture mode: live (real-time), manual (PCAP file), or scan (TCP Port Scan)")
    parser.add_argument("--interface", default="",
                        help="Network interface for live capture (default: auto)")
    parser.add_argument("--pcap", default="",
                        help="Path to PCAP file for manual mode")
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum number of events to capture (0 = unlimited)")
    parser.add_argument("--preferred-tool", choices=["auto", "scapy", "tshark"], default="auto",
                        help="Preferred capture tool")
    parser.add_argument("--mongo-uri", default="",
                        help="MongoDB connection URI for event persistence")
    parser.add_argument("--mongo-db", default="dns_sinkhole",
                        help="MongoDB database name")
    parser.add_argument("--mongo-collection", default="dns_events",
                        help="MongoDB collection name")
    parser.add_argument("--sinkhole-ip", default="",
                        help="IP address to actively spoof for high-threat domains (Active Sinkholing)")
    parser.add_argument("--scan-target", default="",
                        help="Target IP or CIDR for TCP DNS scan (e.g. 192.168.1.0/24)")
    args = parser.parse_args()

    if args.mode == "manual" and not args.pcap:
        emit({"kind": "error", "message": "Manual mode requires --pcap argument."})
        return 1

    if args.limit < 0:
        emit({"kind": "error", "message": "Limit must be a non-negative integer."})
        return 1

    emit({
        "kind": "status",
        "status": "starting",
        "tool": args.preferred_tool,
        "note": f"Preparing DNS monitor in {args.mode} mode with threat analysis enabled.",
    })

    if args.mode == "scan":
        result = run_tcp_dns_scan(args)
    elif args.preferred_tool == "tshark":
        result = parse_tshark(args)
    elif args.preferred_tool == "scapy":
        result = parse_scapy_packets(args)
    elif shutil.which("tshark"):
        emit({
            "kind": "status",
            "status": "starting",
            "tool": "tshark",
            "note": "Auto-detected TShark for capture.",
        })
        result = parse_tshark(args)
    else:
        emit({
            "kind": "status",
            "status": "starting",
            "tool": "scapy",
            "note": "TShark not found, falling back to Scapy.",
        })
        result = parse_scapy_packets(args)

    # Flush any remaining MongoDB batch
    flush_mongo_batch(args)

    return result


if __name__ == "__main__":
    try:
        exit_code = main()
        emit_session_summary()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        emit_session_summary()
        emit({
            "kind": "status",
            "status": "interrupted",
            "note": "DNS monitor interrupted by user (Ctrl+C).",
        })
           