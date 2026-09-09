"""Traffic dissection for UNENCRYPTED frames only — on your own network.

What this does: parses cleartext protocol metadata (DNS queries, HTTP request
lines/headers, TLS *SNI* which is plaintext metadata, ARP, DHCP hostnames) and
aggregate flows from a capture you legally hold. Frames carrying the 802.11
Protected bit are skipped outright, counted, and never touched: this module
contains no WPA/WE-P decryption, no key handling and no cracking, and it is
not intended to. Auditing that your own clients don't leak cleartext
credentials is the use case.
"""
from __future__ import annotations

import csv
import os
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .util import human_bytes, log

HTTP_PORTS = {80, 81, 88, 8000, 8008, 8080, 8081, 8888, 5000}
METHOD_RE = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE) "
                       rb"(\S+) (HTTP/\d(?:\.\d)?)\r\n", re.M)
CRED_KEY_RE = re.compile(rb"(?i)(pass(word|wd)?|pwd|secret|token|apikey|api_key|auth)=")


@dataclass
class Event:
    ts: float
    src_mac: str
    dst_mac: str
    src: str                  # ip:port or host
    dst: str
    proto: str                # DNS / HTTP / TLS-SNI / ARP / DHCP
    summary: str
    detail: str = ""
    alert: str = ""           # "cleartext-credentials", "captive-portal", ...


@dataclass
class Flow:
    src: str
    dst: str
    proto: str
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    notes: set = field(default_factory=set)


class Dissector:
    """Feed frames in, get protocol events + flows out.

    Weakness #6 (traffic-analysis exposure): collection is metadata-minimal
    by default and redaction is ON unless explicitly disabled:

    * HTTP: URL query strings/fragments stripped, User-Agent reduced to its
      product token, POST bodies and Authorization values NEVER logged.
    * DNS: query names truncated; response addresses capped.
    * DHCP: hostnames truncated (owner names leak through them).
    * ``anonymize_ips`` additionally masks IPs to /24 (off by default so
      flows still correlate on your own network; enable for shared reports).
    """

    def __init__(self, redact: bool = True, anonymize_ips: bool = False,
                 max_detail: int = 150):
        self.events: List[Event] = []
        self.flows: Dict[Tuple, Flow] = {}
        self.protected_skipped = 0
        self.frames_seen = 0
        self.ip_frames = 0
        self.redact = redact
        self.anonymize_ips = anonymize_ips
        self.max_detail = max_detail
        self.redactions = 0

    def _ip(self, ip: str) -> str:
        if self.anonymize_ips and ip:
            from .privacy import mask_ip
            # keep "ip:port" shape — mask the host part only
            if ":" in ip and ip.count(":") == 1:
                host, _, port = ip.partition(":")
                return f"{mask_ip(host)}:{port}"
            return mask_ip(ip)
        return ip

    def _emit(self, ev: Event) -> Event:
        self.events.append(ev)
        return ev

    # ----------------------------------------------------------- frame -> IP

    @staticmethod
    def _l3(pkt) -> Optional[Tuple[object, str, str]]:
        """Return (IP/ARP layer, src_mac, dst_mac) for cleartext frames only."""
        from scapy.all import ARP, Dot11, Ether, IP
        src = dst = ""
        if pkt.haslayer(Dot11):
            d = pkt[Dot11]
            src = d.addr2 or ""
            dst = d.addr1 or ""
            fcf = str(d.FCfield)
            wep = getattr(d, "WEP", 0) or 0
            if "protected" in fcf or "wep" in fcf.lower() or wep:
                return "PROTECTED"                    # sentinel
            raw = bytes(d.payload)
            body = None
            if raw[:3] == b"\xaa\xaa\x03":             # LLC/SNAP
                body = raw[8:]
            elif raw[:1] == b"\x45" or (raw[:1] and raw[0] >> 4 == 4
                                        and len(raw) > 40):
                body = raw
            if body is None:
                return None
            try:
                l3 = IP(body) if body[0] >> 4 == 4 else None
            except Exception:
                l3 = None
            if l3 is None:
                return None
            return l3, src, dst
        if pkt.haslayer(IP):
            e = pkt.getlayer(Ether)
            return (pkt[IP], (e.src if e else ""), (e.dst if e else ""))
        if pkt.haslayer(ARP):
            e = pkt.getlayer(Ether)
            return (pkt[ARP], (e.src if e else ""), (e.dst if e else ""))
        return None

    # ------------------------------------------------------------- dissect

    def feed(self, pkt) -> Optional[Event]:
        self.frames_seen += 1
        out = self._l3(pkt)
        if out == "PROTECTED":
            self.protected_skipped += 1
            return None
        assert not isinstance(out, str)
        if out is None:
            return None
        l3, src_mac, dst_mac = out
        from scapy.all import ARP, TCP, UDP, DNS, DNSQR, BOOTP, DHCP
        ts = float(getattr(pkt, "time", time.time()))
        if isinstance(l3, ARP):
            op = "who-has" if l3.op == 1 else "is-at"
            return self._emit(Event(ts, src_mac, dst_mac, l3.psrc, l3.pdst,
                                    "ARP", f"{op} {l3.pdst} tell {l3.psrc}".strip(),
                                    f"snd {l3.psrc} -> {l3.hwdst}"))
        if not hasattr(l3, "payload"):
            return None
        self.ip_frames += 1
        l4 = l3.payload
        lname = type(l4).__name__
        proto = lname if lname in ("TCP", "UDP") else ""
        sport = dport = 0
        payload = b""
        flags = ""
        try:
            if hasattr(l4, "sport"):
                sport, dport = int(l4.sport), int(l4.dport)
            if hasattr(l4, "payload"):
                payload = bytes(l4.payload)
            if proto == "TCP":
                flags = str(l4.flags)
        except Exception:
            pass
        sip, dip = l3.src, l3.dst
        self._flow(proto or "IP", sip, sport, dip, dport,
                   len(bytes(l3)), ts, flags)

        ev: Optional[Event] = None
        from .privacy import (redact_hostname_in_text, redact_url,
                              redact_user_agent, scrub_credentials, truncate)
        sip_r, dip_r = self._ip(sip), self._ip(dip)
        # --- DNS (UDP/TCP 53)
        if l4.haslayer(DNS) and (sport == 53 or dport == 53):
            dns = l4[DNS]
            names = []
            try:
                q = dns.qd
                while q is not None and getattr(q, "qname", None):
                    names.append(q.qname.decode(errors="replace").rstrip("."))
                    q = q.qdnext if hasattr(q, "qdnext") else None
                    if len(names) > 4:
                        break
            except Exception:
                pass
            if not names and dns.an:
                names = [f"{dns.rrname.decode(errors='replace').rstrip('.')} "
                         f"({dns.rrtype})"] if hasattr(dns, "rrname") else []
            ans = ""
            if dns.an and hasattr(dns.an, "rdata"):
                try:
                    rdata = ",".join(str(r.rdata) for r in _iter_rr(dns.an))
                    if self.anonymize_ips:
                        from .privacy import mask_ip as _m
                        rdata = ",".join(_m(x.strip()) for x in rdata.split(","))
                    ans = " -> " + rdata[:120]
                except Exception:
                    ans = ""
            qtype = "query" if dns.qr == 0 else "response"
            summary = f"{qtype} {','.join(names)[:150]}{ans}"
            ev = Event(ts, src_mac, dst_mac, f"{sip_r}:{sport}", f"{dip_r}:{dport}",
                       "DNS", truncate(scrub_credentials(summary), self.max_detail))
            joined = " ".join(names).lower()
            if any(k in joined for k in ("gstatic.com/generate_204", "detective",
                                         "connectivitycheck", "captive.apple",
                                         "nmcheck", "wpad")):
                ev.alert = "captive-portal-probe"
        # --- HTTP (cleartext)
        elif dport in HTTP_PORTS or sport in HTTP_PORTS:
            m = METHOD_RE.search(payload[:4096]) if payload else None
            if m:
                method, url = m.group(1).decode(), m.group(2).decode(errors="replace")
                host = ""
                hm = re.search(rb"(?i)^Host: ?(.+)\r\n", payload[:4096], re.M)
                if hm:
                    host = hm.group(1).decode(errors="replace").strip()
                ua = b""
                um = re.search(rb"(?i)^User-Agent: ?(.+)\r\n", payload[:4096], re.M)
                if um:
                    ua = um.group(1)[:80]
                alert = ""
                head, sep, body = payload.partition(b"\r\n\r\n")
                if method == "POST" and CRED_KEY_RE.search((body or head)[:2048]):
                    alert = "cleartext-credentials"   # values intentionally NOT logged
                elif b"Authorization: Basic" in head:
                    alert = "cleartext-basic-auth"
                if self.redact:
                    url = redact_url(url)
                    self.redactions += 1
                else:
                    url = url[:120]
                ua_s = redact_user_agent(ua) if self.redact else \
                    ua.decode(errors="replace")
                ev = Event(ts, src_mac, dst_mac, f"{sip_r}:{sport}", f"{dip_r}:{dport}",
                           "HTTP", truncate(f"{method} {url} host={host[:60] or '?'}",
                                            self.max_detail),
                           truncate(f"ua={ua_s}" if ua_s else "", self.max_detail),
                           alert)
        # --- TLS ClientHello SNI (plaintext metadata only)
        if (dport == 443 or sport == 443) and payload[:1] == b"\x16":
            sni = tls_sni(payload)
            if sni:
                if self.redact and len(sni) > 80:
                    sni = sni[:80] + "…"
                    self.redactions += 1
                ev = Event(ts, src_mac, dst_mac, f"{sip_r}:{sport}", f"{dip_r}:443",
                           "TLS-SNI", f"ClientHello sni={sni}",
                           "encrypted-payload-skipped")
        # --- DHCP hostnames
        elif l4.haslayer(BOOTP):
            b = l4[BOOTP]
            hostn = dhcp_hostname(b)
            ciaddr = getattr(b, "yiaddr", "")
            if hostn:
                if self.redact:
                    hostn = redact_hostname_in_text(hostn)
                ev = Event(ts, src_mac, dst_mac, sip_r, dip_r, "DHCP",
                           truncate(f"lease yiaddr={ciaddr} hostname={hostn}",
                                    self.max_detail))
        if ev:
            self.events.append(ev)
        return ev

    def _flow(self, proto, sip, sport, dip, dport, size, ts, flags=""):
        a, b = (sip, sport), (dip, dport)
        if (a > b) or (a == b and dport < sport):
            a, b = b, a
        key = (proto, f"{a[0]}:{a[1]}", f"{b[0]}:{b[1]}")
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = Flow(key[1], key[2], proto or "IP")
        f.packets += 1
        f.bytes += size
        f.first = f.first or ts
        f.last = ts
        if "SYN" in flags and "ACK" not in flags:
            f.notes.add("open")

    # -------------------------------------------------------------- export

    def events_rows(self) -> List[dict]:
        return [{"time": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(e.ts)),
                 "ts": round(e.ts, 3), "src_mac": e.src_mac,
                 "dst_mac": e.dst_mac, "src": e.src, "dst": e.dst,
                 "proto": e.proto, "summary": e.summary, "detail": e.detail,
                 "alert": e.alert} for e in self.events]

    def flows_rows(self) -> List[dict]:
        return [{"src": f.src, "dst": f.dst, "proto": f.proto,
                 "packets": f.packets, "bytes": f.bytes,
                 "bytes_h": human_bytes(f.bytes),
                 "first": time.strftime("%H:%M:%S", time.localtime(f.first)),
                 "last": time.strftime("%H:%M:%S", time.localtime(f.last)),
                 "notes": "|".join(sorted(f.notes))}
                for f in sorted(self.flows.values(), key=lambda x: -x.bytes)]

    def stats(self) -> dict:
        return {"frames_seen": self.frames_seen, "ip_frames": self.ip_frames,
                "protected_skipped": self.protected_skipped,
                "events": len(self.events), "flows": len(self.flows),
                "redactions": self.redactions,
                "redact_mode": self.redact,
                "alerts": sum(1 for e in self.events if e.alert)}


def _iter_rr(rr):
    while rr is not None:
        yield rr
        rr = rr.annext if hasattr(rr, "annext") else None


def tls_sni(payload: bytes) -> str:
    """Parse the Server Name Indication from a raw TLS ClientHello.

    SNI is unauthenticated plaintext metadata; we read only that field and
    never touch keys, finished messages or anything post-encryption.
    """
    # 16 ver(2) reclen(2) | 01 hlen(3) ver(2) random(32) sid_len sid
    # csl cs comp comp extlen [etype elen ...]*
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        i = 5 + 1 + 3 + 2 + 32                            # -> sid_len byte
        sid = payload[i]
        i += 1 + sid
        cs_len = struct.unpack("!H", payload[i:i + 2])[0]
        i += 2 + cs_len
        i += 1 + payload[i]                                # compression
        ext_end = i + 2 + struct.unpack("!H", payload[i:i + 2])[0]
        i += 2
        while i + 4 <= min(ext_end, len(payload)):
            etype, elen = struct.unpack("!HH", payload[i:i + 4])
            i += 4
            if etype == 0x0000 and i + 5 <= len(payload):   # server_name
                nlen = struct.unpack("!H", payload[i + 3:i + 5])[0]
                return payload[i + 5:i + 5 + nlen].decode(errors="replace")
            i += elen
    except (IndexError, struct.error):
        pass
    return ""


def dhcp_hostname(bootp) -> str:
    """Option 12 (Host Name) from raw BOOTP options."""
    try:
        for opt in bootp.options:
            if isinstance(opt, tuple) and opt[0] == 12:
                return bytes(opt[1]).decode(errors="replace")
            if isinstance(opt, (bytes, bytearray)) and opt[:1] == b"\x0c":
                return opt[2:].decode(errors="replace")
    except Exception:
        pass
    s = getattr(bootp, "sname", b"") or b""
    return s.strip(b"\x00").decode(errors="replace") if s else ""


# --------------------------------------------------------------- front-ends

def analyze_pcap(path: str, max_frames: int = 0, redact: bool = True,
                 anonymize_ips: bool = False) -> Dissector:
    """Dissect a capture file (pcap/pcapng, RadioTap or Ethernet linktype)."""
    from scapy.all import PcapReader
    d = Dissector(redact=redact, anonymize_ips=anonymize_ips)
    n = 0
    with PcapReader(path) as rd:
        for pkt in rd:
            try:
                d.feed(pkt)
            except Exception as exc:
                log.debug("dissect skip: %s", exc)
            n += 1
            if max_frames and n >= max_frames:
                break
    return d


def analyze_live(iface: str, duration: float = 30.0,
                 on_event: Optional[callable] = None, redact: bool = True,
                 anonymize_ips: bool = False) -> Dissector:
    """Live pass-through dissection on an interface you own (root).

    Only frames visible in the air without decryption are parsed — i.e. your
    open network / management-plane metadata. Everything protected is skipped.
    """
    from scapy.all import sniff
    d = Dissector(redact=redact, anonymize_ips=anonymize_ips)

    def cb(pkt):
        try:
            ev = d.feed(pkt)
            if ev and on_event:
                on_event(ev)
        except Exception:
            pass

    log.info("live dissecting %s for %.0fs (cleartext frames only)...",
             iface, duration)
    try:
        sniff(iface=iface, prn=cb, store=False, timeout=duration, monitor=True)
    except Exception:
        sniff(iface=iface, prn=cb, store=False, timeout=duration)
    return d


def export(outdir: str, prefix: str, d: Dissector) -> List[str]:
    from .privacy import secure_file
    os.makedirs(outdir, exist_ok=True)
    files = []
    for name, cols, rows in (
            ("traffic_events.csv",
             ["time", "ts", "src_mac", "dst_mac", "src", "dst", "proto",
              "summary", "detail", "alert"], d.events_rows()),
            ("traffic_flows.csv",
             ["src", "dst", "proto", "packets", "bytes", "bytes_h", "first",
              "last", "notes"], d.flows_rows())):
        p = os.path.join(outdir, f"{prefix}_{name}")
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        secure_file(p)
        files.append(p)
        log.info("wrote %-42s (%d rows)", p, len(rows))
    return files


def print_dissector(d: Dissector, limit: int = 40) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        c = Console()
        t = Table(title=f"Traffic events ({len(d.events)})", box=box.ROUNDED,
                  header_style="bold blue", expand=True)
        for col in ("Time", "Src", "Dst", "Proto", "Summary", "Alert"):
            t.add_column(col, max_width=44 if col == "Summary" else None)
        for e in d.events[-limit:]:
            t.add_row(time.strftime("%H:%M:%S", time.localtime(e.ts)),
                      e.src, e.dst,
                      f"[bold]{e.proto}[/]",
                      e.summary + (f"\n[dim]{e.detail}[/]" if e.detail else ""),
                      f"[red]{e.alert}[/]" if e.alert else "")
        c.print(t)
        f = Table(title=f"Top flows ({len(d.flows)})", box=box.SIMPLE,
                  header_style="bold blue")
        for col in ("A", "B", "Pkts", "Bytes", "Notes"):
            f.add_column(col)
        for row in d.flows_rows()[:limit]:
            f.add_row(row["src"], row["dst"], str(row["packets"]),
                      row["bytes_h"], row["notes"])
        c.print(f)
    except ImportError:
        print(f"\nTraffic events ({len(d.events)}):")
        for e in d.events[-limit:]:
            al = f"  !!{e.alert}" if e.alert else ""
            print(f"  {time.strftime('%H:%M:%S', time.localtime(e.ts))} "
                  f"[{e.proto}] {e.src} -> {e.dst}: {e.summary}{al}")
    s = d.stats()
    print(f"  frames={s['frames_seen']} ip={s['ip_frames']} "
          f"protected-skipped={s['protected_skipped']} "
          f"flows={s['flows']} alerts={s['alerts']}")
