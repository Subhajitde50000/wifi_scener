# -*- coding: utf-8 -*-
"""credlab — credential & session security analysis laboratory (13).

An offline, instructor-controlled laboratory: a seeded generator produces a
*lab-only* capture (`lesson.pcap`) with two intentionally paired scenarios:

  LEG  A — plaintext protocols (HTTP basic + form login, FTP, Telnet,
            SNMPv1 community strings, cookie/session ID over HTTP)
  LEG  B — the same day's work over TLS (TLS 1.3-style handshake with the
            same endpoints): headers/records identical shapes, secrets
            hidden.

Students dissect the capture with the CLI or the web portal; they name
back what a passive watcher could steal in leg A, prove how little of it
remains in leg B, and read the detectors the lab ships (insecure-auth
subset of the known-answer rules). Score mode grades their attribution and
their defence mapping.

Credentials are instructor-generated and synthetic by construction
(plaintext-credential fields carry ROT13-style laboratory markers like
`LAB-STUDENT-03:s3cr3t-lab-13` — visibly fake by prefix `LAB-`). The
generator NEVER imports, reads, or reconstructs any real credential from
anywhere: inputs are a seed and a count.

Everything is simulator-grade: pcaps are real (we re-use the repo's
Radiotap pcap writer), frames are real bytes — the "insecurity" is a
property of the *auth bytes we deliberately place* in the capture.
"""

import hashlib
import html
import json
import os
import struct
import sys
import threading
import time
from collections import defaultdict

from .devlab import DevLabStore, new_token, _page  # noqa: E402
from .privacy import secure_file  # noqa: E402
from .wpalab import write_pcap, _RADIOTAP8  # noqa: E402

LINKTYPE_RAW_IPV4 = 101      # DLT_RAW so tcpdump/wireshark open it directly


# ------------------------------------------------------- synthetic identity

def _mk_identities(rnd, n_students=6):
    """Instructor-generated lab accounts. Visibly synthetic."""
    mons = ["wren", "tiger", "heron", "otter", "finch", "viper"]
    ids = []
    for i in range(n_students):
        uname = f"LAB-STUDENT-{i + 1:02d}"
        pw = f"{rnd.choice(mons)}-{1000 + rnd.randint(0, 8999)}-lab"
        token = hashlib.sha1(f"{uname}:{pw}".encode()).hexdigest()[:24]
        ids.append(dict(username=uname, password=pw,
                        cookie=f"SESSID_lab_{rnd.randint(0, 9999)}",
                        api_key=f"labkey-{token}",
                        community=rnd.choice(["labpublic", "labprivate",
                                              "labro"]),
                        realm="lab.example.local"))
    return ids


# --------------------------------------------------------- frame builders

def build_credential_fixture(path, seed=13, fresh=True, students=6):
    """Two-leg capture: plaintext leg then TLS leg. Deterministic per seed.

    Layout in the pcap (raw IPv4 linktype):
      beacons-less; packets are deliberately sequential and small.
    """
    import random as _r
    rnd = _r.Random(seed)
    if os.path.exists(path) and not fresh:
        raise FileExistsError(f"{path} exists (fresh=False)")
    ids = _mk_identities(rnd, students)
    t0 = time.time() - 3600
    records = []
    srv_ip = b"\x0a\x63\x00\x21"     # 10.63.0.33 lab server
    seq = [rnd.randint(100, 900)]

    def nextseq(obs=220):
        seq[0] += obs
        return seq[0]

    def tcp_packet(sport, dport, payload, src, ts, flags=0x18):
        s, d = seq[0], nextseq()
        l4 = (struct.pack("!HHII", sport, dport, s, d)
              + struct.pack("!BBH", 0x50, flags, 64240)
              + struct.pack("!HH", 0, 0))
        total = 20 + len(l4) + len(payload)
        l3 = (struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, nextseq() % 65000,
                          0, 64, 6, 0, src, srv_ip) + l4 + payload)
        records.append((t0 + ts, l3))

    # -------------------------------------------------- leg A: plaintext
    for i, ident in enumerate(ids):
        cli = bytes([10, 63, 0, 60 + i])
        t = 60 + i * 40
        # HTTP basic
        auth = base64_creds(ident["username"], ident["password"])
        payload = (f"GET /lab/inventory HTTP/1.1\r\nHost: {ident['realm']}\r\n"
                   f"Authorization: Basic {auth}\r\n"
                   f"Cookie: {ident['cookie']}\r\n\r\n").encode()
        tcp_packet(50000 + i, 80, payload, cli, t)
        # HTTP form POST
        form = (f"POST /lab/login HTTP/1.1\r\nHost: {ident['realm']}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                f"user={ident['username']}&pass={ident['password']}"
                f"&next=/lab").encode()
        tcp_packet(50010 + i, 80, form, cli, t + 5)
        # FTP
        ftp = f"USER {ident['username']}\r\nPASS {ident['password']}\r\n" \
              f"QUIT\r\n".encode()
        tcp_packet(50020 + i, 21, ftp, cli, t + 10)
        # Telnet (login banner + typed creds per byte-ish, grouped)
        tel = (f"login: {ident['username']}\r\nPassword: "
               f"{ident['password']}\r\n$ ").encode()
        tcp_packet(50030 + i, 23, tel, cli, t + 15)
        # SNMPv1 GET with community string
        comm = ident["community"].encode()
        snmp = bytes([0x30, 26 + len(comm), 0x02, 1, 0,
                      0x04, len(comm)]) + comm + bytes.fromhex(
            "a00e02010102010002010030053003060100")
        records.append((t0 + t + 20, struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(snmp),
            rnd.randint(1, 60000), 0, 64, 17, 0, cli, srv_ip)
            + struct.pack("!HHHH", 50040 + i, 161, 8 + len(snmp), 0)
            + snmp))
        # HTTP cookie echo (same cookie, again — replayability)
        payload = (f"GET /lab/roster HTTP/1.1\r\nHost: {ident['realm']}\r\n"
                   f"Cookie: {ident['cookie']}\r\n\r\n").encode()
        tcp_packet(50050 + i, 80, payload, cli, t + 25)

    # -------------------------------------------------- leg B: TLS same work
    for i, ident in enumerate(ids):
        cli = bytes([10, 63, 1, 60 + i])
        t = 60 + i * 40 + 18000
        # handshake ClientHello (record-layer silhouette is cleartext by
        # design in TLS; hostname visible via SNI; nothing else survives)
        ch = b"\x16\x03\x03" + struct.pack("!H", 64) + rnd.randbytes(60)
        tcp_packet(51000 + i, 443, ch, cli, t)
        sh = b"\x16\x03\x03" + struct.pack("!H", 42) + rnd.randbytes(38)
        records.append((t0 + t + 1, _ip_pkt(443, 51000 + i, sh, srv_ip,
                                            cli)))
        # encrypted application data (opaque)
        for k in range(6):
            app = b"\x17\x03\x03" + struct.pack("!H", rnd.randint(40, 200))
            tcp_packet(51000 + i, 443, app + rnd.randbytes(len(app) - 5),
                       cli, t + 2 + k)
    write_pcap(path, records, linktype=LINKTYPE_RAW_IPV4)
    return dict(path=path, frames=len(records), identities=ids,
                seed=seed)


def base64_creds(u, p):
    import base64
    return base64.b64encode(f"{u}:{p}".encode()).decode()


def _ip_pkt(sport, dport, payload, src, dst):
    l4 = (struct.pack("!HHII", sport, dport, 1000, 2000)
          + struct.pack("!BBH", 0x50, 0x18, 64240) + struct.pack("!HH",
                                                                 0, 0))
    total = 20 + len(l4) + len(payload)
    return (struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 4321, 0, 64, 6,
                        0, src, dst) + l4 + payload)


def load_fixture_meta(path):
    return dict(path=path, size=os.path.getsize(path) if
                os.path.exists(path) else 0)


# ------------------------------------------------------------- dissection

def read_raw_pcap(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise ValueError("too small for pcap")
    magic = blob[:4]
    order = "<" if magic in (b"\xd4\xc3\xb2\xa1",) else ">"
    linktype = struct.unpack(order + "I", blob[20:24])[0]
    frames = []
    off = 24
    while off + 16 <= len(blob):
        ts_s, ts_f, incl, _ = struct.unpack_from(order + "IIII", blob, off)
        off += 16
        if off + incl > len(blob):
            break
        frames.append((ts_s + ts_f / 1e6, blob[off:off + incl]))
        off += incl
    return linktype, frames


def dissect_capture(path):
    """Packet analysis of the lab capture → exposure rows (leg A) +
    TLS leg summary rows (leg B)."""
    link, frames = read_raw_pcap(path)
    exposures = []       # what a passive watcher steals from plaintext
    tls_rows = []        # what survives under encryption
    stats = defaultdict(int)

    def ipv4(body):
        if len(body) < 20 or (body[0] >> 4) != 4:
            return None
        ihl = (body[0] & 0xF) * 4
        proto = body[9]
        return dict(src=".".join(str(b) for b in body[12:16]),
                    dst=".".join(str(b) for b in body[16:20]),
                    proto=proto, off=ihl, total=len(body))

    def tcp(body, o):
        if len(body) < o["off"] + 20:
            return None
        l4 = body[o["off"]:]
        sport, dport = struct.unpack("!HH", l4[:4])
        off = ((l4[12] >> 4) & 0xF) * 4
        return dict(sport=sport, dport=dport,
                    payload=l4[off:])

    def udp(body, o):
        l4 = body[o["off"]:]
        sport, dport, length = struct.unpack("!HHH", l4[:6])
        return dict(sport=sport, dport=dport,
                    payload=l4[8:length])

    for ts, body in frames:
        o = ipv4(body)
        if not o:
            continue
        if o["proto"] == 6:
            t = tcp(body, o)
            if not t:
                continue
            pl = t["payload"]
            dport = t["dport"]
            stats["tcp"] += 1
            if dport == 80:
                stats["http"] += 1
                txt = pl.decode("utf-8", "ignore")
                mline = txt.splitlines()[0] if txt else ""
                for line in txt.splitlines():
                    if line.lower().startswith("authorization:"):
                        cred = line.split(":", 1)[1].strip()
                        try:
                            import base64 as b64
                            decoded = b64.b64decode(
                                cred.split()[-1]).decode("utf-8", "ignore")
                        except Exception:
                            decoded = "(undecodable)"
                        exposures.append(dict(
                            when=ts, proto="http-basic", line=mline[:80],
                            field="Authorization", leaked=decoded,
                            src=o["src"], dst=o["dst"]))
                    if line.lower().startswith("cookie:"):
                        exposures.append(dict(
                            when=ts, proto="http-cookie", line=mline[:80],
                            field="Cookie", leaked=line.split(":", 1)[1]
                            .strip(), src=o["src"], dst=o["dst"]))
                # form credentials on POST
                if txt.startswith("POST") and "&pass=" in txt or \
                        txt.startswith("POST") and "pass=" in txt:
                    body_part = txt.split("\r\n\r\n", 1)[-1]
                    kv = dict(p.split("=", 1) for p in
                              body_part.split("&") if "=" in p)
                    if "user" in kv and "pass" in kv:
                        exposures.append(dict(
                            when=ts, proto="http-form",
                            line=mline[:80], field="form body",
                            leaked=f"{kv['user']} : {kv['pass']}",
                            src=o["src"], dst=o["dst"]))
            elif dport == 21:
                stats["ftp"] += 1
                txt = pl.decode("utf-8", "ignore")
                if txt.startswith("USER") or "PASS" in txt:
                    leaks = [ln.split(" ", 1) for ln in
                             txt.splitlines() if ln.upper()
                             .startswith(("USER", "PASS"))]
                    for verb, val in leaks:
                        exposures.append(dict(
                            when=ts, proto="ftp", line=txt.splitlines()[0]
                            [:60], field=verb, leaked=val,
                            src=o["src"], dst=o["dst"]))
            elif dport == 23:
                stats["telnet"] += 1
                txt = pl.decode("utf-8", "ignore")
                if "login:" in txt and "Password:" in txt:
                    seg = txt.split("login:", 1)[-1]
                    user = seg.splitlines()[0].strip()
                    pw = seg.split("Password:", 1)[-1].splitlines()[0].strip()
                    exposures.append(dict(
                        when=ts, proto="telnet", line="telnet session",
                        field="login", leaked=f"{user} : {pw}",
                        src=o["src"], dst=o["dst"]))
            # TLS leg: positive identification of opaque records
            if dport == 443 and pl[:1] in (b"\x16", b"\x17"):
                stats["tls"] += 1
                kind = {b"\x16": "handshake", b"\x17": "application-data"}[
                    pl[:1]]
                tls_rows.append(dict(when=ts, kind=kind,
                                     size=len(pl) - 5 if len(pl) > 5 else 0,
                                     src=o["src"], dst=o["dst"],
                                     readable=("SNI hostname only"
                                               if kind == "handshake"
                                               and len(pl) > 40 else
                                               "opaque — keys never "
                                               "left the wire")))
        elif o["proto"] == 17:
            u = udp(body, o)
            stats["udp"] += 1
            if u and u["dport"] == 161 and len(u["payload"]) > 8 \
                    and u["payload"][0] == 0x30:
                stats["snmp"] += 1
                pl = u["payload"]
                try:
                    ln = pl[7]
                    comm = pl[8:8 + ln].decode("utf-8", "ignore")
                except Exception:
                    comm = "(malformed)"
                exposures.append(dict(when=ts, proto="snmpv1",
                                      line="SNMPv1 GET",
                                      field="community", leaked=comm,
                                      src=o["src"], dst=o["dst"]))
    return dict(exposures=exposures, tls=tls_rows, stats=dict(stats),
                frames=len(frames))


# --------------------------------------------------- detectors and analysis

def exposure_summary(rows):
    """One line per protocol: what a passive watcher could steal, and how
    often."""
    bag = defaultdict(lambda: defaultdict(int))
    for r in rows:
        bag[r["proto"]]["leaks"] += 1
        bag[r["proto"]][r["field"]] += 1
    out = []
    redes = {
        "http-basic": "the username:password pair, base64 (which is "
                      "encoding, NOT encryption — one line decodes it)",
        "http-form": "the plaintext credential posted into a form body",
        "http-cookie": "the live session cookie — replay = full account "
                       "without ever knowing the password",
        "ftp": "plaintext USER/PASS on the wire since 1971",
        "telnet": "every keystroke, including the password as typed",
        "snmpv1": "the community string (it's a device password)",
    }
    risks = {
        "http-basic": "credential theft → account takeover",
        "http-form": "credential theft → account takeover",
        "http-cookie": "session hijack-right-now, even w/o the password",
        "ftp": "credential theft + control channel takeover",
        "telnet": "full keystroke feed: everything, forever",
        "snmpv1": "device impersonation + management-plane reads",
    }
    for proto, d in sorted(bag.items()):
        out.append(dict(proto=proto, leaks=d["leaks"],
                        fields=sorted(x for x in d if x != "leaks"),
                        steal=redes.get(proto, "credentials on the wire"),
                        risk=risks.get(proto, "credential exposure")))
    return out


def insecure_alerts(rows):
    """Alert entries the lab raiser when an insecure protocol appeared."""
    out = []
    for proto in ("http-basic", "http-form", "telnet", "ftp", "snmpv1",
                  "http-cookie"):
        subset = [r for r in rows if r["proto"] == proto]
        if subset:
            out.append(dict(
                proto=proto, count=len(subset),
                msg=(f"ALERT: insecure-auth protocol on the wire: {proto} "
                     f"×{len(subset)} — credentials/tokens in cleartext "
                     f"(lab traffic)"),
                first=subset[0]["when"],
                last=subset[-1]["when"]))
    return out


def protection_summary(tls_rows):
    """What the TLS leg exposes: handshake metadata only."""
    hs = [r for r in tls_rows if r["kind"] == "handshake"]
    app = [r for r in tls_rows if r["kind"] == "application-data"]
    return dict(handshake_records=len(hs),
                visible="SNI hostname + record layer framing (by design)",
                encrypted=len(app),
                invisible="username, password, cookie, token, body — all "
                          "inside the AEAD channel",
                note="same requests as leg A; nothing readable now")


# ------------------------------------------------------------------ scoring

CRED_QUIZ = {
    "q_http_basic": 15, "q_cookie": 20, "q_telnet": 15, "q_snmp": 10,
    "q_tls_hide": 25, "q_mitigation": 15,
}


def score_credlab(answers):
    fb = []
    pts = 0.0
    # Q1 decode the basic-auth header
    a = (answers.get("q_http_basic") or "")
    if a == "base64-is-encoding":
        pts += CRED_QUIZ["q_http_basic"]
        fb.append("✅ Q1: right — base64 is *encoding*, anyone can decode")
    else:
        fb.append("❌ Q1: base64 is encoding, not protection")
    # Q2 cookie = session token
    a = (answers.get("q_cookie") or "")
    if a == "session-hijack":
        pts += CRED_QUIZ["q_cookie"]
        fb.append("✅ Q2: right — replaying a cookie IS account take-over "
                  "without knowing a password")
    else:
        fb.append("❌ Q2: replay the cookie, you ARE the user")
    # Q3 telnet reading level
    a = (answers.get("q_telnet") or "")
    if a == "keystroke-level":
        pts += CRED_QUIZ["q_telnet"]
        fb.append("✅ Q3: correct — telnet is keystroke-transparent")
    else:
        fb.append("❌ Q3: telnet sends every typed byte in the clear")
    # Q4 snmp community
    a = (answers.get("q_snmp") or "")
    if a == "community":
        pts += CRED_QUIZ["q_snmp"]
        fb.append("✅ Q4: correct — the community string is the password")
    else:
        fb.append("❌ Q4: the community IS the credential in v1/v2c")
    # Q5 what TLS hides
    a = (answers.get("q_tls_hide") or "")
    if a == "everything-but-sni":
        pts += CRED_QUIZ["q_tls_hide"]
        fb.append("✅ Q5: correct — SNI sticks out by design; everything "
                  "else is AEAD")
    else:
        fb.append("❌ Q5: TLS hides credentials/cookies/body — only the "
                  "SNI hostname and framing are visible")
    # Q6 mitigation answer
    a = (answers.get("q_mitigation") or "")
    if a == "eol-plaintext-protocols":
        pts += CRED_QUIZ["q_mitigation"]
        fb.append("✅ Q6: correct — the fix is lifecycle: retire the "
                  "cleartext protocols, not the users")
    else:
        fb.append("❌ Q6: mitigations are systemic: HTTPS/SFTP/SSH/SNMPv3, "
                  "and never sending secrets like these")
    total = sum(CRED_QUIZ.values())
    return dict(score=round(100.0 * pts / total, 1),
                points=round(pts, 1), possible=total, feedback=fb,
                answers=answers)


def cred_exercises() -> str:
    items = [
        ("1. Raw anatomy", "`cred-lab dissect lesson.pcap` — how many "
         "exposures, on which protocols, with which field each time?"),
        ("2. Steal it yourself", "`cred-lab exposures lesson.pcap` — "
         "reconstruct ONE stolen login from a Basic header (base64 "
         "yourself with the printable hint) and one session cookie. Try "
         "to replay both in your head: what distinguishes those cases?"),
        ("3. Count the listeners", "How many OTHER devices saw those "
         "packets? (hub/switch/wifi broadcast review. Everyone within "
         "reach when it's plaintext.)"),
        ("4. The protected twin", "`cred-lab tls lesson.pcap` — same "
         "identities, same actions, SNI visible, everything else opaque. "
         "What *exactly* did TLS take away from the watcher?"),
        ("5. Protocol triage", "`cred-lab alerts lesson.pcap` — for each "
         "alerted protocol name ONE modern replacement and ONE "
         "organisational action (kill list, HSTS, MFA, allowlist, "
         "…)"),
        ("6. Write the memo", "`cred-lab report lesson.pcap -o out/` — "
         "hand the generated CSV+markdown bundle to your partner and have "
         "them redo exercise 2 WITHOUT seeing leg A first: out of the "
         "capture's context, how much of the answer can they "
         "reconstruct?"),
        ("7. Scored", "`cred-lab score lesson.pcap --answers ans.json` — "
         "which concept was hardest: the *encoding* (base64) or the "
         "*replay* (cookie)?"),
    ]
    return ("Cred-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


# ================================================================== web app

class CredWebApp:
    """Student portal + instructor console for the credential lab."""

    def __init__(self, capture, identities, store: DevLabStore, token: str):
        self.capture = capture
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.identities = identities
        self.analysis = None
        self._analyze()

    def _analyze(self):
        with self.lock:
            self.analysis = dissect_capture(self.capture)
            self.summary = exposure_summary(self.analysis["exposures"])
            self.alerts = insecure_alerts(self.analysis["exposures"])
            self.tls = protection_summary(self.analysis["tls"])

    def regenerate(self):
        """Destroy the current synthetic identities and build fresh ones —
        same capture path. Returns the new seed."""
        with self.lock:
            regens = getattr(self, "_regens", 0) + 1
            self._regens = regens
            seed_val = 13 + regens
            meta = build_credential_fixture(self.capture, seed=seed_val,
                                            fresh=True)
            self.identities = meta["identities"]
            self._analyze()
            if self.store:
                self.store.event("cred", "regenerate",
                                 f"seed={seed_val}")
            return seed_val

    def _nav(self):
        return ("<nav><a class='btn ghost' href='/'>🏠 brief</a>"
                "<a class='btn ghost' href='/exposures'>🔓 exposures</a>"
                "<a class='btn ghost' href='/tls'>🛡 tls leg</a>"
                "<a class='btn ghost' href='/compare'>⚖️ side-by-side</a>"
                "<a class='btn ghost' href='/alerts'>🚨 alerts</a>"
                "<a class='btn ghost' href='/quiz'>✅ quiz</a>"
                "<a class='btn ghost' href='/exercises'>🧭 exercises</a>"
                "</nav>")

    def home(self):
        s = self.summary
        f = self.analysis["frames"]
        leak = len(self.analysis["exposures"])
        card = f"""
 <div class='hero'><h1>🔑 Credential &amp; session security lab</h1>
  <p>A single capture containing two versions of the same dramatic day:
  credentials in the clear — and then the same work hiding behind TLS.
  You are the passive watcher. Inventory everything readable in leg A;
  then prove leg B took it away.</p>
  <p class='small'>All identities are instructor-generated synthetic lab
  accounts (<code>LAB-STUDENT-…</code>) into <code>lab.example.local</code>;
  secrets are marked fakes. Nothing real was, or could be, captured.</p>
 </div>
 <div class='grid'>
  <div class='card'><h2>capture</h2><p>{f} frames · {leak} exposure rows ·
   {len(self.analysis['tls'])} TLS records · insecure-auth alerts: "
   f"{len(self.alerts)}</p></div>
  <div class='card'><h2>protocol census (leg A)</h2><ul>
   {''.join(f'<li><b>{x["proto"]}</b> — {x["leaks"]} leaks '
            f'({", ".join(x["fields"])})</li>' for x in s)}</ul></div>
 </div>
 <div class='card'><h2>The one-line lesson</h2>
  <p class='tag warn'>base64 is not encryption; a cookie is a bearer
  instrument; and telnet has been broadcasting your keystrokes since
  1969 — TLS is boring because nothing leaks.</p></div>"""
        return _page("cred lab — brief", self._nav() + card)

    def exposures_page(self):
        rows = self.analysis["exposures"][:400]
        tr = "".join(
            f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(r['when']))}"
            f"</td><td>{html.escape(r['proto'])}</td>"
            f"<td>{html.escape(r['field'])}</td>"
            f"<td class='mono'>{html.escape(r['leaked'])}</td>"
            f"<td>{html.escape(r['src'])} → {html.escape(r['dst'])}</td></tr>"
            for r in rows)
        sums = "".join(
            f"<tr><td><b>{html.escape(s['proto'])}</b></td>"
            f"<td>{s['leaks']}</td><td>{html.escape(', '.join(s['fields']))}</td>"
            f"<td>{html.escape(s['steal'])}</td>"
            f"<td>{html.escape(s['risk'])}</td></tr>" for s in self.summary)
        body = self._nav() + f"""
 <div class='card'><h2>🔓 exposures (leg A) — what the watcher steals</h2>
  <table><tr><th>time</th><th>proto</th><th>field</th><th>value out of
  the wire</th><th>flow</th></tr>{tr}</table></div>
 <div class='card'><h2>protocol summary</h2>
  <table><tr><th>proto</th><th>leaks</th><th>fields</th><th>what's
  readable</th><th>risk</th></tr>{sums}</table></div>"""
        return _page("exposures", body)

    def tls_page(self):
        rows = self.analysis["tls"][:400]
        tr = "".join(
            f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(r['when']))}"
            f"</td><td>{html.escape(r['kind'])}</td><td>{r['size']} B</td>"
            f"<td>{html.escape(r['src'])} → {html.escape(r['dst'])}</td>"
            f"<td>{html.escape(r['readable'])}</td></tr>" for r in rows)
        t = self.tls
        body = self._nav() + f"""
 <div class='card'><h2>🛡 leg B — the same traffic over TLS</h2>
  <p>records: {t['handshake_records']} handshake +
     {t['encrypted']} application-data · visible: <b>{t['visible']}</b> ·
     opaque: <b>{t['invisible']}</b></p>
  <p class='small'>{html.escape(t['note'])}</p>
  <table><tr><th>time</th><th>kind</th><th>size</th><th>flow</th>
   <th>readable</th></tr>{tr}</table></div>"""
        return _page("tls leg", body)

    def compare_page(self):
        left = "".join(f"<li><b>{html.escape(s['proto'])}</b>: "
                       f"{html.escape(s['steal'])}</li>" for s in self.summary)
        body = self._nav() + f"""
 <div class='card'><h1>⚖️ same day, twice</h1>
  <div style='display:flex;gap:16px;flex-wrap:wrap'>
   <div style='flex:1;min-width:300px'><h2>🩸 leg A — plaintext</h2>
    <ul>{left}</ul></div>
   <div style='flex:1;min-width:300px'><h2>🛡 leg B — TLS</h2>
    <ul><li><b>every record</b>: {html.escape(self.tls['visible'])}</li>
     <li><b>gone</b>: {html.escape(self.tls['invisible'])}</li></ul></div>
  </div></div>"""
        return _page("side by side", body)

    def alerts_page(self):
        al = "".join(f"<div class='card'><b>[{html.escape(a['proto'])}]"
                     f"</b> {html.escape(a['msg'])}"
                     f" <span class='small'>{a['count']} occurrence(s)</span>"
                     f"</div>" for a in self.alerts)
        return _page("alerts", self._nav() + (
            "<div class='card'><h2>🚨 insecure-auth alerts</h2>"
            "<p class='small'>Every alert is triggered by cleartext this "
            "lab generated on purpose — and each alert's presence here is "
            "precisely why legacy protocols belong on kill-lists.</p></div>"
            + al))

    def quiz_page(self):
        body = self._nav() + f"""
 <div class='card'><h2>✅ Scored quiz</h2>
  <form method='post' action='/quiz'>
   <div class='card'><h3>Q1. The 'Authorization: Basic …' value holds the
     credential in…</h3>
    <select name='q_http_basic'><option value=''>—</option>
     <option value='base64-is-encoding'>base64 — an encoding, trivially
      decoded</option>
     <option value='encrypted'>an encrypted blob</option>
     <option value='hashed'>a one-way hash</option></select></div>
   <div class='card'><h3>Q2. Whoever captures a live session cookie can…
     </h3>
    <select name='q_cookie'><option value=''>—</option>
     <option value='session-hijack'>replay it and BE the user, password-free
      </option>
     <option value='decode-pw'>recover the password from it</option>
     <option value='nothing'>do nothing — cookies look random</option>
    </select></div>
   <div class='card'><h3>Q3. Telnet's exposure granularity is…</h3>
    <select name='q_telnet'><option value=''>—</option>
     <option value='keystroke-level'>every keystroke/password char, as
      typed</option>
     <option value='login'>just the login banner</option>
     <option value='none'>nothing, telnet is old so it's obscure</option>
    </select></div>
   <div class='card'><h3>Q4. An SNMP v1 capture betrays…</h3>
    <select name='q_snmp'><option value=''>—</option>
     <option value='community'>the community string — the device password
      </option>
     <option value='oids'>only OIDs, nothing sensitive</option></select></div>
   <div class='card'><h3>Q5. Under TLS, the watcher learns…</h3>
    <select name='q_tls_hide'><option value=''>—</option>
     <option value='everything-but-sni'>the SNI hostname + framing; nothing
      of the secrets</option>
     <option value='everything'>everything, TLS is theatrical</option>
     <option value='headers'>HTTP headers only</option></select></div>
   <div class='card'><h3>Q6. The mitigation strategy is…</h3>
    <select name='q_mitigation'><option value=''>—</option>
     <option value='eol-plaintext-protocols'>retire cleartext protocols
      systemically (HTTPS/SFTP/SSH/SNMPv3)</option>
     <option value='user-training'>train users to type faster under MRI
      shielding</option></select></div>
   <button class='btn ok'>🏁 submit</button></form></div>"""
        return _page("quiz", body)

    def quiz_submit(self, answers, ip=""):
        r = score_credlab(answers)
        self.store.attempt("cred", "quiz", json.dumps(answers),
                           r["score"], json.dumps(r["feedback"]), ip)
        lines = "".join(f"<li>{html.escape(f)}</li>" for f in r["feedback"])
        return _page("quiz result", self._nav() + (
            f"<div class='card'><h2>Result: {r['score']}/100</h2>"
            f"<ul>{lines}</ul><a class='btn info' href='/quiz'>retry</a>"
            f"</div>"))

    def exercises_page(self):
        return _page("exercises", self._nav() + (
            "<div class='card'><h2>🧭 worksheet</h2><pre>"
            + html.escape(cred_exercises()) + "</pre></div>"))

    def instructor(self, token):
        funnel = self.store.funnel("cred")
        att = self.store.attempts("cred", 50)
        idrows = "".join(
            f"<tr><td><code>{i['username']}</code></td>"
            f"<td><code class='mono'>{i['password']}</code></td>"
            f"<td><code>{i['cookie']}</code></td>"
            f"<td><code>{i['community']}</code></td></tr>"
            for i in self.identities)
        atr = "".join(f"<tr><td>{a['time']}</td><td>quiz</td>"
                      f"<td><b>{a['score']}</b></td></tr>"
                      for a in att) or \
              "<tr><td colspan=3>no attempts yet</td></tr>"
        body = f"""
 <div class='hero'><h1>👩‍🏫 CRED-lab instructor console</h1>
  <p class='small'>Synthetic identities ONLY. Rotating these recreates the
  capture with fresh lab credentials; nothing here corresponds to real
  peoples' accounts.</p></div>
 <div class='grid'>
  <div class='card'><h2>lab identities (synthetic)</h2>
   <table><tr><th>user</th><th>password (lab)</th>
    <th>cookie (lab)</th><th>community</th></tr>{idrows}</table></div>
  <div class='card'><h2>controls</h2>
   <button class='btn info' id='gb'>🔁 regenerate identities + capture</button>
   <button class='btn danger' id='rb'>🧹 wipe attempts log</button>
   <a class='btn ghost' href='/'>student view</a>
   <p>funnel: {funnel}</p>
   <p class='small'>regeneration = 'destroy' in lab semantics: the old
   synthetic credentials vanish with the process.</p></div>
 </div>
 <div class='card'><h2>quiz attempts ({len(att)})</h2>
  <table><tr><th>time</th><th>q</th><th>score</th></tr>{atr}</table></div>
 <script>
 const TOKEN={json.dumps(token)};
 async function rst(){{if(!confirm('Wipe attempts?'))return;
  await fetch('/api/reset?token='+TOKEN,{{method:'POST'}});location.reload();}}
 async function regen(){{if(!confirm('Destroy ALL lab credentials and '+
  'rebuild with fresh synthetic ones?'))return;
  const r=await fetch('/api/regenerate?token='+TOKEN,{{method:'POST'}});
  const d=await r.json();alert('fresh identities (seed '+d.seed+'), '+
  d.frames+' frames');location.reload();}}
 document.getElementById('rb').addEventListener('click',rst);
 document.getElementById('gb').addEventListener('click',regen);
 </script>"""
        return _page("instructor — cred lab", body)


def make_cred_server(bind, port, app: CredWebApp):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class H(BaseHTTPRequestHandler):
        server_version = "wifiscanner-credlab"
        protocol_version = "HTTP/1.1"
        _MAX_POST = 65536

        def log_message(self, *a):
            pass

        def _ok(self, s):
            if isinstance(s, str):
                s = s.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(s)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(s)

        def _json(self, obj, code=200):
            s = json.dumps(obj, indent=1).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(s)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(s)

        def _client(self):
            return self.client_address[0] if self.client_address else "?"

        def _tok_ok(self, u):
            q = parse_qs(u.query)
            return q.get("token", [""])[0] == app.token

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path
            if path.startswith("/i/"):
                token = path[len("/i/"):]
                if token != app.token:
                    return self._json({"error": "not found"}, 404)
                app.store.event("cred", "page-view", "instructor",
                                self._client())
                return self._ok(app.instructor(token))
            app.store.event("cred", "page-view", path, self._client())
            if path == "/":
                return self._ok(app.home())
            if path == "/exposures":
                return self._ok(app.exposures_page())
            if path == "/tls":
                return self._ok(app.tls_page())
            if path == "/compare":
                return self._ok(app.compare_page())
            if path == "/alerts":
                return self._ok(app.alerts_page())
            if path == "/exercises":
                return self._ok(app.exercises_page())
            if path == "/quiz":
                return self._ok(app.quiz_page())
            if path == "/api/state":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                return self._json({"ok": True,
                                   "funnel": app.store.funnel("cred"),
                                   "exposures": len(
                                       app.analysis["exposures"]),
                                   "alerts": len(app.alerts),
                                   "identities": len(app.identities)})
            return self._json({"error": "not found"}, 404)

        def _form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > self._MAX_POST:
                return None
            if n == 0:
                return {}
            raw = self.rfile.read(n).decode("utf-8", "ignore")
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def do_POST(self):
            u = urlparse(self.path)
            path = u.path
            form = self._form()
            if form is None:
                return self._json({"error": "bad request"}, 400)
            if path == "/quiz":
                return self._ok(app.quiz_submit(
                    {k: form.get(k, "") for k in CRED_QUIZ},
                    self._client()))
            authed = self._tok_ok(u)
            def _need():
                return self._json({"error": "not found"}, 404)
            if path == "/api/reset":
                if not authed:
                    return _need()
                n = app.store.reset("cred")
                return self._json({"ok": True, "removed": n})
            if path == "/api/regenerate":
                if not authed:
                    return _need()
                seed = app.regenerate()
                return self._json({"ok": True, "seed": seed,
                                   "frames": app.analysis["frames"],
                                   "count": len(app.identities)})
            return self._json({"error": "not found"}, 404)

    return ThreadingHTTPServer((bind, port), H)
