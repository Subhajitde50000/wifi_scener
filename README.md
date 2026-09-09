# wifi_scener

**Passive Wi-Fi survey · client attribution · presence history · sensor-grid
positioning · raw capture · cleartext-traffic audit · wireless IDS ·
hardening reports · 802.11 frame anatomy — one terminal tool, everything in
CSV/JSON/HTML.**

Version 4.1.0 · Python ≥ 3.8 · Linux/macOS/Windows · zero mandatory
dependencies · receive-only except for one consent-gated defensive self-test,
a local synthetic-credential phishing-awareness lab (`lab`), and an offline
WPA decryption laboratory working only on lab captures with lab key material
(`wpa-lab`).

```
 __      __.__  _____.__    _________
/  \    /  \  |/ ____\  |  /   _____/ ___________  ____   ___________
\   \/\/   /  \   __\|  |  \_____  \_/ ___\__  \ /    \_/ __ \_  __ \
 \        /|  ||  |  |  |  /        \  \___/ __ \   |  \  ___/|  | \/
  \__/\  / |__||__|  |__| /_______  /\___  >____  /___|  /\___  >__|
       \/                         \/     \/     \/     \/     \/
```

---

## Table of contents

1. [What it is / isn't](#1-what-it-is--isnt)
2. [Feature matrix](#2-feature-matrix)
3. [How device counting without joining works](#3-how-device-counting-without-joining-works)
4. [Install](#4-install)
5. [Hardware for monitor mode](#5-hardware-for-monitor-mode)
6. [Quick start](#6-quick-start)
7. [Architecture](#7-architecture)
8. [Command reference (every flag)](#8-command-reference)
9. [Output artefacts (every file, every column)](#9-output-artefacts)
10. [SQLite history schema & queries](#10-sqlite-history-schema--queries)
11. [Methodology (every metric, exactly how it is computed)](#11-methodology)
12. [Sensor-grid positioning guide](#12-sensor-grid-positioning-guide)
13. [The IDS: signatures it detects](#13-the-ids-signatures-it-detects)
14. [Operational recipes](#14-operational-recipes)
15. [Python API](#15-python-api)
16. [Testing](#16-testing)
17. [Platform support & limitations](#17-platform-support--limitations)
18. [Troubleshooting FAQ](#18-troubleshooting-faq)
19. [Legal & ethics](#19-legal--ethics)
20. [Changelog](#20-changelog)

---

## 1. What it is / isn't

**It is** a professional, passive RF-intelligence and network-ownership
toolkit for *your* airspace: it listens to frames already broadcast, reads
your own router's association table, and analyses captures you legally hold.
Every survey, IDS, audit and history feature is receive-only: it never joins
a network, clones an AP, cracks a key or decrypts anything.

There is exactly **one** transmitting command, `inject`, and it is not an
attack tool — it is a *self-test rig for your own defences*. It answers the
questions passive listening cannot: *"do my IDS sensors actually hear the
channels they claim to?"* (canary markers); *"does enabling PMF/802.11w on my
router really stop deauth kicks?"* (the bounded `pmf-test`); *"can a
deauthentication / disassociation burst knock one of my own clients off?"*
(the bounded, unicast `deauth` test); and *"does my IDS/warden actually catch
an Evil Twin beaconing my SSID?"* (the `evil-twin` **beacon-only** drill).
The evil-twin drill transmits beacons that advertise a network name you own
from a fresh spoofed BSSID for a few, capped seconds — but it has **no
probe-response, authentication, association, DHCP or data path**, so the
result is a radio that is *visible as a fake AP yet cannot accept a client,
capture a handshake/credential or relay traffic*; it is a fire drill for your
detectors, not a working rogue AP. Every transmitting mode is a dry run by
default, requires root plus an explicit `--authorized` assertion (`--yes` for
any frame that disconnects a client or impersonates an SSID), is hard
rate/duration-capped per run (the small PMF probe stays below the IDS flood
threshold; the deauth test and beacon drill are bounded, self-terminating,
never a loop), refuses broadcast/wildcard/third-party targets, and writes an
owner-only audit record of every frame. `ids-selftest` mode synthesises the
attack signatures **offline, with no radio at all** and is safe in CI.

**It isn't** — and never will be, whatever the use-case framing — an attack
kit. These capabilities are **deliberately absent by design**:

| Not in this tool | What ships instead |
|---|---|
| Decrypt WPA/WPA2/WPA3 traffic | Protected frames are skipped and *counted*; `traffic` proves what leaks *without* encryption so you can fix it |
| Deauth/disassoc **floods**, broadcast/wildcard kicking, loops | `ids` detects deauth *and* disassociation floods live; `inject` sends only a bounded, one-shot, **unicast** burst at a device you name — either a tiny below-threshold PMF probe (`pmf-test`) or an explicit authorised pen-test burst (`deauth`, hard-capped, `--yes` required) |
| Working rogue/evil-twin AP (that accepts clients, captures handshakes/credentials, or relays traffic) | `ids` + `scan` detect rogue BSSIDs and cloned SSIDs; `inject --mode evil-twin` runs a **beacon-only** detection drill (a fake-looking AP that nothing can join) so you can verify those detectors fire |
| Handshake capture for cracking | `ids` fires a **critical** alert when someone harvests handshakes against you; `frames --handshakes` explains the protocol |
| Unrestricted packet injection / frame replay | The only transmit path (`inject`) is consent-gated, target-restricted to your own infrastructure, fully audited, and offers nothing but canary markers, ordinary active-scan probes and bounded, logged, unicast deauth/disassoc self-tests |
| Jamming / continuous channel flooding | Hard per-mode frame caps and a minimum inter-frame interval; every transmission is one bounded run, never a loop — sustained denial-of-service is not expressible in the CLI |
| De-anonymising randomized MACs | Randomised addresses are *flagged* for reporting honesty, never correlated back to people |
| Indefinite bystander tracking | `record` refuses to run unless pointed at your own network; probe sightings stay ephemeral |

Learning the attacks is still on the menu — through `frames` (byte-level
anatomy of every frame type), `audit` (what each weakness exposes you to and
how to close it) and `ids` (what each attack *looks like* on the wire).

---

## 2. Feature matrix

| # | Capability | Command(s) | Root? | Needs monitor mode? |
|---|---|---|---|---|
| 1 | Survey all nearby networks, A-to-Z per AP | `scan`, `detail`, `offline` | no | no |
| 2 | Count devices connected to any AP, without joining | `monitor`, `devices`, `full` | yes | yes |
| 3 | Full client census of your own network (assoc table + RF + LAN) | `own` | optional | optional |
| 4 | Presence over time (who was on, when; roster; sessions) | `record`, `presence` | no | no |
| 5 | Device location from multiple sensors/APs (trilateration) | `locate` | no | no (from history) |
| 6 | Movement trails + zone dwell time + ASCII map | `trail` | no | no |
| 7 | Per-scan device detail: signal, traffic, probes, vendor, privacy MACs | all | mixed | mixed |
| 8 | Raw 802.11 frame capture: streaming pcap, rotation, ring buffer | `capture` | yes | yes |
| 9 | Cleartext traffic dissection (DNS/HTTP/SNI/ARP/DHCP/flows) | `traffic` | no (pcap) / yes (live) | yes (live only) |
| 10 | Passive wireless IDS (floods, harvest chains, beacon mutation, rogues) | `ids` | yes (live) / no (pcap) | yes (live only) |
| 11 | Hardening audit: weakness → attack → fix, MD checklist | `audit` | no | no |
| 12 | Frame-by-frame 802.11 education | `frames` | no | no |
| 13 | Channel congestion + recommended channels | `scan`, `watch` | no | no |
| 14 | Rogue/evil-twin detection | `scan` (`*_rogue_alerts.csv`) | no | no |
| 15 | LAN inventory (IPs, hostnames, ports, nmap integration) | `own`, `devices --lan` | no | no |
| 16 | Live dashboard | `watch` | no | optional |
| 17 | Structured export: 5 CSVs + JSON + HTML + Markdown | `-o --format` everywhere | no | no |
| 18 | **Authorized** packet injection: offline IDS signature self-test (incl. disassoc-flood), active probe scan, IDS coverage canaries, bounded own-AP PMF check, bounded unicast **deauth/disassoc** test, and a **beacon-only Evil-Twin detection drill** (no serving/credential/data path) | `inject` | no (selftest) / yes (live) | yes (live only) |
| 19 | Captive-portal phishing **awareness lab**: fake Wi-Fi login portal, synthetic test accounts, submission detection/logging, live instructor dashboard, attacker-view debrief, spot-the-fake indicators, legit-vs-phishing comparison, one-click reset — all LOCAL, no RF, synthetic credentials only | `lab` | no | no |
| 20 | **WPA/WPA2/WPA3 decryption laboratory**: real 4-way-handshake parsing and offline key verification (MIC), authorised CCMP-128/256 + GCMP decryption of lab captures with lab key material (passphrase/PSK/PMK), GTK broadcast recovery, missing-handshake + wrong-key failure cases, before/after visibility tables, fixture generator, guided exercises, student+instructor web UIs — stdlib crypto checked against FIPS-197/RFC 3610/4493/3394/NIST-GCM vectors | `wpa-lab` | no | no (works on pcap files) |
| 21 | **MAC randomization & deanonymization laboratory**: synthetic multi-sensor probe dataset (Radiotap pcaps), evidence engine with named support/anti-evidence and graduated hypothesis verdicts, rotation hand-offs, twin-decoy false-positive trap (simultaneity defeats fingerprint merging), scored clustering exercise, student portal + token-gated instructor dashboard with one-click fresh-dataset regeneration | `mac-lab` | no | no (synthetic dataset) |
| 22 | **Long-term device tracking laboratory**: 2-week synthetic multi-sensor history — visit sessionization, weekday/hour heatmaps, dwell, movement edges, short vs long retention contrast, decoy (same-OUI) attribution trap, MAC-rotating visitor proving the privacy defence works, scored quiz, student portal + instructor dashboard with reset + regenerate | `track-lab` | no | no (synthetic dataset) |
| 23 | **Hidden monitoring & stealth detection laboratory**: synthetic 4-day host telemetry (procs/conns/files/auth.log/services) with a concealed implant — install, night-flip, ps-vs-ss concealment, audit gap, repawn+rename, unlink-while-running; explainable signal engine, behaviour-change alerts, authorised-vs-covert comparison, scored hunt, instructor console (tick control, reset, regenerate) | `stealth-lab` | no | no (synthetic telemetry) |
| 24 | **Automatic (offensive) response laboratory**: seeded IDS events on designated lab test devices, rulebook R1–R6 (aggressive R6 ships disabled), modes dry-run / approval / auto / manual, simulated firewall state, approval queue, rollback, full detect→decide→respond→result audit trail, FP metrics incl. the friendly-fire trap (R6 + no allowlist = your own scanner blocked) | `response-lab` | no | no (simulated lab network) |
| 25 | **Large-scale scanning & scope-control laboratory**: virtual lab estate (10.77.*) with services/online flags/duplicate-IP conflicts; simulated concurrent scans with live progress + rate limiting; scope sentinel refusing non-inventoried/out-of-subnet targets before probing with loud alerts; targeted-vs-uncontrolled comparison; CSV export; instructor expand/reset/regenerate | `scan-lab` | no | no (virtual estate) |
| 26 | **Credential & session security laboratory**: lab-generated capture twins plaintext and TLS legs of the same synthetic identities — base64 basic-auth, form posts, FTP, Telnet keystrokes, SNMPv1 community strings, replayable cookies all decoded and counted; TLS leg proven opaque except SNI; insecure-auth alert table; report bundle; instructor regenerates/destroys identities at will | `cred-lab` | no | no (lab capture) |

---

## 3. How device counting without joining works

802.11 data frames carry up to four MAC addresses plus To-DS/From-DS flags.
Even fully encrypted, the **headers are plaintext**, and they state exactly
which client talks to which access point:

| Frame (type/subtype) | Field seen | What it proves |
|---|---|---|
| Data/QoS, To-DS=1 | `addr2` = client, `addr3` = AP | this client is **associated** with that AP |
| Data/QoS, From-DS=1 | `addr1` = client, `addr2` = AP | same binding, downlink direction |
| Association / Reassociation Request (0/0, 0/2) | `addr2→addr3` | definitive join event |
| EAPOL (key type, over LLC/SNAP 0x888E) | AP of `addr3` | a device just (re)authenticated |
| Beacon / Probe Response (0/8, 0/5) | full IE set | AP fingerprint (security, channel, load…) |
| Probe Request (0/4) | `addr2` + SSID element | a nearby (unassociated) device and the networks it remembers |
| Deauth / Disassoc (0/12, 0/11) | `addr1/addr3` | churn, or an attack in progress (`ids` watches this) |

Signal strength is taken from the radiotap header per frame, so clients get
RSSI, min/max, and distance estimates too. Locally-administered address
detection (bit 1 of byte 0) marks privacy MACs.

---

## 4. Install

```bash
git clone <repo> && cd wifi_scener
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # scapy (capture/monitor) + rich (UI)
python3 main.py interfaces               # capability self-check
```

| Piece | Needed for | Install |
|---|---|---|
| **scapy** | monitor capture, `capture`, `traffic`, `frames`, offline analysis, pcap import | `pip install scapy` |
| **rich** | colour tables/panels (graceful ASCII fallback without it) | `pip install rich` |
| `iw` | Linux survey + `iw dev … station dump` own-AP table + monitor setup | `apt install iw` |
| `nmcli` | Windows-free Linux survey fallback | (NetworkManager, usually present) |
| `nmap` | auto-detected; LAN inventory becomes faster/richer | `apt install nmap` (optional) |
| `airmon-ng` | alternative monitor-mode bring-up (`--airmon`) | `apt install aircrack-ng` (optional; only the monitor-mode part is ever used) |

Everything degrades gracefully: without scapy the survey/LAN/history/audit
commands work; the ones that need it tell you exactly what to install.

Install as a package (optional, gives a `wifiscanner` command):

```bash
pip install -e .            # setup.py defines entry_points wifiscanner=wifiscanner.cli:main
wifiscanner interfaces
```

---

## 5. Hardware for monitor mode

Monitor mode is needed for: `monitor`, `capture`, `ids` live, `traffic --live`,
and the over-the-air client counting inside `own`/`full`/`devices`.

* **Linux** is the reference platform. Works out of the box with most
  Atheros (`ath9k`, `ath10k`), MediaTek (`mt76`), Ralink (`rt2x00`) chips.
  Check yours: `iw list | grep -A6 "Supported interface modes" | grep monitor`.
* **Avoid**: most Broadcom (wl) and Intel cards do unreliable/unsupported
  monitor injection-free capture on Linux/macOS. A $15 TL-WN722N **v1** (ath9k_htc)
  or any mt7601u/mt76x2u USB adapter is the classic choice.
* **macOS**: monitor mode is effectively unavailable on modern Macs
  (Apple removed it); use a USB Linux box as sensor, `scan`/`offline` locally.
* **Windows**: no monitor mode via the normal driver stack — survey works
  (`netsh wlan`); capture on a Pi/Linux sensor, analyse the pcap on Windows.
* Built-in cards on laptops are usually fine on Linux (check `iw list`).

You can always verify what *your* box can do:

```bash
python3 main.py interfaces
# platform / root? / survey backends available / scapy present / OUI size / adapter list
```

---

## 6. Quick start

```bash
# 1 — See everything nearby (10 s, no root):
python3 main.py scan

# 2 — Same, exported for Excel / pandas / your notes:
python3 main.py scan -o output --format csv json html md

# 3 — YOUR network, fully (assoc table + LAN names/ports):
python3 main.py own --ports

# 4 — Keep a presence history of your network (Ctrl-C stops):
python3 main.py record --db home.sqlite --lan

# 5 — Ask it questions:
python3 main.py presence --db home.sqlite --since -24h
python3 main.py presence --db home.sqlite --known

# 6 — 24/7 raw capture you can hand to anyone later:
sudo python3 main.py capture -i wlan0 -d 86400 -o day.pcap \
     --rotate-mb 64 --ring-segments 16

# 7 — What did anyone's cleartext actually leak on YOUR network:
python3 main.py traffic day.pcap -o out/

# 8 — Is anything trying deauth/harvest/clone tricks right now:
sudo python3 main.py ids -i wlan0 -d 3600 --db home.sqlite --follow

# 9 — How do I harden this:
python3 main.py audit -o reports/

# 10 — Understand every frame you captured:
python3 main.py frames day.pcap --limit 40
```

Full tour with a sample capture, no hardware:

```bash
python3 tests/make_fixture.py
python3 main.py offline tests/fixture.pcap -o demo/ --format csv json html md
python3 main.py traffic tests/fixture.pcap
python3 main.py ids --pcap tests/fixture.pcap
python3 main.py frames tests/fixture.pcap --filter beacon
```

---

## 7. Architecture

```
                        ┌────────────────────────────────────────────┐
   OS tools             │              Engine (merge)                │
 ┌─ iw / nmcli ────────►│  one record per BSSID, richer-wins merge   │
 ├─ airport / netsh ───►│  AP → {clients: STA objects w/ RSSI stats} │
 ├─ monitor sniffer ───►│  + unassociated devices (probing)          │
 │   (scapy, passive)   │  analytics: security grading, congestion,  │
 ├─ LAN sweep (ARP/     │  rogue detection, summary, presence,       │
 │   DNS/ports/nmap) ──►│  fixes — see modules below                 │
 └─ warden baseline ────┴───────┬───────────────┬─────────────┬──────┘
                                │               │             │
                        export.py          store.py       defense.py
                        5×CSV, JSON,       SQLite: scans,  Watchdog IDS +
                        HTML, Markdown     devices, obs.,   hardening audit
                                           sessions, fixes,
                                           warden           frames.py
                        cli.py (18 cmds) ──► display.py     frame anatomy
                        argparse, wiring     rich/ASCII      (educational)
                                             inject.py  (off by default,
                                            dry run, gated self-test TX)
```

| Module | Responsibility |
|---|---|
| `wifiscanner/models.py` | `AccessPoint`/`Station` dataclasses, RF math (channel↔freq, path-loss ranging, quality), security score/grade/risk rules, per-binding evidence + census breakdown |
| `wifiscanner/oui.py` | OUI vendor DB, MAC normalisation, randomized + multicast detection |
| `wifiscanner/backends/survey.py` | `iw`/`nmcli`/`iwlist`/`airport`/`system_profiler`/`netsh` parsers → AP objects |
| `wifiscanner/backends/sniffer.py` | monitor-mode bring-up (`iw`/`airmon-ng`), passive 802.11 collector: full IE/RSN parsing, To-DS/From-DS attribution, channel hopping, streaming pcap writer (rotate + ring) |
| `wifiscanner/backends/lan.py` | own-AP `station dump` table, ARP/ping sweep, PTR hostnames, TCP port sweep, nmap integration, current-connection facts |
| `wifiscanner/engine.py` | multi-source merge (richer wins), congestion, best channels, rogue detection, summary |
| `wifiscanner/store.py` | SQLite persistence: scans/networks/devices/observations/fixes/warden, session splitting, time parsing |
| `wifiscanner/locate.py` | range model, WLS trilateration/bilateration, nearest-sensor fallback, sanity guard, zones, dwell, ASCII map |
| `wifiscanner/traffic.py` | cleartext dissector (DNS/HTTP/TLS-SNI/ARP/DHCP), flows, credential alerts (redacted) |
| `wifiscanner/defense.py` | IDS Watchdog (7 detectors), hardening `audit_ap` |
| `wifiscanner/frames.py` | frame-by-frame annotated 802.11 anatomy |
| `wifiscanner/inject.py` | the *only* transmitter: frame builders (probe/deauth/**disassoc**/**beacon**, both directions), consent+privilege gates, hard frame/duration caps, owner-only audit CSV, offline `run_ids_selftest` (deauth + disassoc signatures), kick/PMF verdict, canary analysis, and the **beacon-only** evil-twin detection drill; dry run by default |
| `wifiscanner/export.py` | CSV×5 / JSON / styled HTML / Markdown writers |
| `wifiscanner/display.py` | rich tables/panels with full plain-text fallback |
| `wifiscanner/wcrypto.py` | stdlib-only AES/CCM/GCM/CMAC/KW/RC4/WEP/TKIP-Michael + PTK/PMK derivation, pinned to published vectors |
| `wifiscanner/wpalab.py` | WPA-lab engine & fixtures: pcap/Radiotap/802.11/RSN/EAPOL parsing, MIC key verification, authorised CCMP/GCMP decryption, GTK unwrap, exports, student/instructor web UI |
| `wifiscanner/lab.py` | captive-portal phishing-awareness lab (offline, synthetic credentials, instructor dashboard) |
| `wifiscanner/devlab.py` | mac-lab + track-lab: dataset generators (Radiotap pcaps, ground-truth CSV), correlation engine (support/anti-evidence, twin trap), tracker (visits/patterns/edges/trackability), scoring, both web portals |
| `wifiscanner/cli.py` | argparse surface, 22 commands, guardrails |
| `wifiscanner/wcrypto.py` | stdlib crypto core for `wpa-lab`: AES/CCM/GCM/CMAC/KW/RC4/PBKDF2 pinned to published vectors |
| `wifiscanner/wpalab.py` | WPA/WPA2/WPA3 decryption lab: capture analysis, MIC key verify, authorised decrypt, web portal |
| `wifiscanner/devlab.py` | shared lab store + MAC-randomization lab + device-tracking lab |
| `wifiscanner/hidmon.py` | stealth-detection lab: telemetry scenario, signal engine, alerts, hunt, web |
| `wifiscanner/autoresp.py` | response lab: rule engine, 4 modes, approvals, rollback, audit trail |
| `wifiscanner/scanlab.py` | scan/scope lab: virtual estate, job engine (concurrency + rate limiting), scope sentinel, alerts, web |
| `wifiscanner/credlab.py` | credential security lab: fixture generator (synthetic identities), plaintext/TLS dissector, detector alerts, report export, web |
| `wifiscanner/privlab.py` | privacy lab: synthetic MAC-rotation observation logs, clustering/correlation engine, exposure + scrub report, scope sentinel, web |
| `wifiscanner/rflab.py` | RF resilience lab: metric engine, interferer simulator (start/stop/reset/intensity caps), detector + incident reports, web |
| `wifiscanner/hsaudit.py` | handshake/password-audit lab: tiered synthetic credential+capture generation, MIC-driven offline audit with timing, three-state teaching, web |

---

## 8. Command reference

Global flags: `-v/--verbose` (debug logs), `-q/--quiet`, `--no-banner`,
`--version`. Shared scan-family flags (on `scan monitor full detail devices own
watch offline`): `-i/--interface`, `-o/--output DIR`, `--prefix`,
`--format {csv,json,html,md}…`, `--sort {rssi,clients,ssid,channel,security}`,
`--limit N`, `--db SQLITE` (persist snapshot), `--sensor NAME` (tag rows),
`--retain-days N` (history retention, default 90), `--privacy-mode
{standard,minimal,ephemeral}`, `--anonymize` (salted MAC pseudonyms in exports).
(`locate` reuses a subset — `-i -d --airmon --no-monitor-setup --db` — plus its own
grid flags; `record/presence/trail/capture/traffic/ids/audit/frames` are
standalone and list their flags below.)
Times for `--since/--until`: `'YYYY-MM-DD'`, `'YYYY-MM-DD HH:MM[:SS]'`,
`'HH:MM'` (today), relative `'-2h15m'`, `'now'`.

### `scan` — survey nearby APs
`iw` → `nmcli` → `iwlist` → `airport` → `netsh` auto-selection.
Flags: `--backend {auto,nmcli,iw,iwlist,airport,netsh}`, `--no-rescan`.
Prints: AP table, channel-congestion bars, rogue alerts, summary panel.
`-o` exports, `--db` persists.

### `monitor` — passive device attribution (the core trick)
Puts the card in monitor mode (auto, restore-on-exit — including after
Ctrl-C), hops all 2.4/5 GHz channels (or locks), and attributes every data
frame to AP↔client pairs.
Flags: `-d/--duration` (s, default 60), `-c/--channels 1,6,11`,
`--bands 2.4GHz 5GHz 6GHz`, `--bssid AA:..` (lock one AP: auto-locks its
channel when known from the survey pass), `--hop-interval 0.35`,
`--airmon`, `--no-monitor-setup` (iface already in monitor),
`--write-pcap FILE`.
Requires root + scapy + a monitor-capable NIC; without them it says so
clearly and still shows what the survey pass found.

### `own` — authoritative census of YOUR network
Fuses: (1) `iw dev <iface> station dump` of your own AP if this box hosts it,
(2) survey, (3) monitor capture locked to your BSSID (if root), (4) LAN sweep
— ping sweep, ARP table, PTR hostnames, `(gateway)`, optional `--ports`.
Prints your connection summary then full A-to-Z detail + per-client table.
Flags: `-d` (25 s monitor), `--ports`, `--no-lan`, `--no-monitor`,
`--airmon`, `--no-monitor-setup`.

### `full` — everything at once
`scan` + `monitor` + (with `--lan`) LAN inventory + exports; forces
`-o output` and adds the HTML report. Flags as above + `-d`, `--bands`,
`--lan`, `--ports`.

### `detail <SSID-or-BSSID>` — one network, A-to-Z
Substring match over SSID/BSSID; with root+scapy it runs a short locked
monitor pass (`-d`, default 45 s) first so the client list is populated.
`--no-monitor` skips that.

### `devices` — client-only view
Monitor census (unless `--no-monitor`) and/or `--lan [--subnet 192.168.1.0/24]
[--ports]` for your own network.

### `watch` — live dashboard
Refreshing (default `-n 8` s) table; `--monitor` folds in a short monitor
pass per cycle (root, scapy). Ctrl-C → final export if `-o` given.

### `offline <pcap>` — analyse existing captures
Runs the full monitor parsing pipeline on a pcap/pcapng (RadioTap, Ethernet
or 802.11 linktype). No root, no radio. Accepts all export/DB flags — the
workhorse for field-capture → desk-analysis workflows.

### `capture` — raw frame capture, production storage semantics
Streaming pcap writer (never buffers in RAM): `--rotate-mb 64` starts
`capture-001.pcap`, `-002`, … when a segment exceeds the size;
`--ring-segments 8` makes it a bounded ring (oldest segment overwritten —
fixed disk budget for 24/7). `--analyze` parses into AP/client tables at
exit. Ctrl-C finalises. Flags: `-i -d -c --bands --bssid --hop-interval -o
FILE --rotate-mb --ring-segments --airmon --no-monitor-setup`,
plus the sensitivity guardrails: `--ack-sensitive` (acknowledges captures
hold third-party data; without it you get a loud warning, never a refusal),
`--strip-payloads` (128-byte snaplen: headers for counting/IDS, no payloads),
`--max-age-days N` (delete expired segments on exit). Files are written
owner-only (0600).

### `traffic [pcap] | --live -i IF` — cleartext dissection
Parses only frames visible *without* decryption. Extracts: DNS queries/responses
(+ captive-portal probe flagging), HTTP request line + `Host:` + `User-Agent`,
**TLS SNI** (from a hand-rolled ClientHello parser — metadata only), ARP
`who-has`, DHCP hostnames; aggregates flows (packets/bytes/SYN notes).
Detects **cleartext credentials** (`POST` bodies with password/pwd/token
fields, `Authorization: Basic`) — flagged, **values never logged**. Any frame
with the Protected/WEP bit is skipped and counted.
**Redaction is ON by default**: URL query strings/fragments stripped,
User-Agents reduced to product tokens, hostnames truncated, credential
patterns scrubbed. `--no-redact` disables it (explicit opt-out, warns loudly),
`--anonymize-ips` masks IPs to /24 for shared reports. Output: rich tables +
`traffic_events.csv` + `traffic_flows.csv` with `-o DIR` (`--prefix`).
`--max-frames` (default 200 000), `--limit` rows shown, live mode `-d`.

### `record` — continuous presence history (own network, guarded)
`--db presence.sqlite` (default), loop cadence `-n/--interval 30` s,
`-d/--duration 0` = until Ctrl-C, `--backend`, `--lan` (enrich with IPs/
names), `--sensor NAME` (tag for later lateration),
`--bssid AA:..[,BB:..]` explicit own-AP list.
**Target rule:** without `--bssid`, it auto-targets *your current Wi-Fi
connection*; with neither, it **refuses** (exit 2) rather than persisting
bystander data. `--pcap FILE` = one-shot: import a capture's AP/client model
into the DB and exit. Reaps `iw station dump` automatically when this box
hosts the AP. Prints one status line per pass.
Privacy: `--retain-days N` (default 90, auto-enforced on every open),
`--privacy-mode {standard,minimal,ephemeral}`, `--anonymize` (salted MAC
pseudonyms, no hostnames/IPs). See `db` for pruning, per-device erasure and
whole-DB anonymization.

### `presence` — query the history
`--db`, filters `--mac`, `--ssid`, `--since/-–until`, `--gap 300` (seconds of
absence that ends a session), `--limit 100`, `-o DIR` → `presence_sessions.csv`.
`--known` shows the roster (first/last seen, #APs). Default view = sessions
table + "present NOW" count.

### `locate` — multi-sensor positioning from history
`--sensors sensors.csv` (**required**), `--zones zones.csv`, `--db`,
`--mac` (optional filter), `--window 3.0` (s, fuses per-sensor readings),
`--n-exp 2.7` (path-loss exponent), `--since/--until`, `--recompute`
(store fixes back), `--live -d 20 -i wlan0` (capture first). Output:
per-fix table (`x, y, Unc m, Zone, Method, Sources`) + ASCII map when ≥2
sensors.

### `trail` — movement of one device
`--mac` (**required**), `--db`, optional `--sensors/--zones/--window/
--since/--until`, `--map` (ASCII: `S`ensors, zone outlines, time-gradient
trail `o.:-=+*#%@`), `-o DIR` → `trail-<MAC>.csv` (ts, time, x, y, unc,
zone, method). Without `--sensors` degrades to a presence-only trail
(per-scan rows) rather than failing.

### `ids` — passive wireless IDS
Live: `-i wlan0 -d 60` (root; monitor). Offline: `--pcap FILE`.
Tuning: `--window 10.0` s anomaly window, `--flood 5` frames in window
before “flood”, `--sensitivity {low,medium,high}` (scales the threshold 2×/1×/0.6×).
Every alert carries `confidence` 0-100 + `status` (unconfirmed/corroborated/confirmed)
+ `evidence` and a “to confirm” hint; beacon mutations must persist across beacons
to upgrade, and an adaptive margin raises the bar automatically when the whole
band is noisy. Warden: `--db warden.sqlite --learn` baselines currently
visible APs; every beacon from a BSSID not in the baseline then raises
`unknown-bss`. `--follow` prints alerts as they fire; `-o DIR` exports
`ids_alerts.csv`. Detection only — see §13.

### `audit` — hardening report
Live scan (or `--pcap FILE`, `--ssid filter`); one row per check per BSS:
`PASS/WARN/FAIL + severity + finding/fix`. `-o DIR` writes
`audit_report.md` — a markdown checklist (`[x] [!] [ ]`). See §11.5 for the
exact check list.

### `frames` — 802.11 frame anatomy
`frames capture.pcap [--limit 20] [--filter
beacon|probe-req|assoc-req|deauth|disassoc|data|handshake]`.
Annotates: radiotap metadata, FC flags, address-field semantics,
data-frame To-DS/From-DS binding explanation, protected-bit note, IE-by-IE
beacon decode (SSID, rates incl. legacy-11b note, DS channel, TIM, country,
BSS load, HT/VHT caps, **full RSN decode**: group/pairwise suites, AKM
selectors by IEEE registry name, PMF capable/required bits, vendor/WPS),
LLC/SNAP ethertype, EAPOL **role + flags decoded from bytes** (key
material never rendered). `--handshakes` prints the census: total EAPOL,
per-BSS EAPOL, deauth/disassoc totals — counts only.

### `inject` — authorized, defensive packet injection (self-test only)
The only command that transmits. **It is a dry run by default**: without
`--transmit` it builds frames, prints them and writes the audit trail without
touching the radio. Every live mode needs **root + `--authorized`** (an
assertion that you own the target or hold written test authorization); the
deauth test additionally needs **`--yes`**. Frames are hard rate-capped
(≤ 6 probes / 4 canaries per channel; ≤ 4 deauth frames total — below the
IDS flood threshold of 5), spaced by a minimum interval, may only target a
**unicast** AP+client you name, and every frame is recorded in a 0600
`injection_audit.csv`. Floods, broadcast kicks, AP clones and replay are not
implemented.

| Mode | Purpose | Transmits? |
|---|---|---|
| `--mode ids-selftest` | synthesise deauth-flood, **disassociation-flood**, forced-reauth, beacon-mutation and unknown-BSS signatures **offline** and confirm the watchdog fires (also writes a pcap for `ids --pcap`) | never (no radio, no root) |
| `--mode probe` | ordinary active scanning — the same probe requests every OS sends while scanning; `--ssid` for a directed probe, otherwise wildcard | dry run / guarded live |
| `--mode canary` | emit a distinctive probe-request marker (`--token`, auto-generated) so you can verify each remote IDS/capture sensor logs it (grep the token) | dry run / guarded live |
| `--mode pmf-test` | send a tiny unicast deauth burst at **one of your own clients** (`--bssid` + `--client`), then report whether the client stayed (**PMF works**) or was kicked and re-associated (**PMF missing → fix it**). The burst is capped *below* the IDS flood threshold | requires root + `--transmit --authorized --yes` |
| `--mode deauth` | explicit authorised pen-test of a client's resilience: a bounded, one-shot, **unicast** burst of deauthentication and/or disassociation frames. `--frame-type {deauth,disassoc,both}`, `--direction {ap-to-sta,sta-to-ap}`, `--count N` (hard-capped). Observes and reports whether the client disconnected/re-associated (**vulnerable to kick**) or ignored the frames (**protected**) | requires root + `--transmit --authorized --yes` |
| `--mode evil-twin` | **beacon-only** rogue-AP detection drill: for `--duration N` (hard-capped, self-terminating) it beacons `--ssid <YOUR-OWN-name>` from a fresh spoofed BSSID on `-c CH`, advertising `--security {open,wpa2}`, so your warden/rogue detectors have something to catch. It sends **only beacons** — no probe responses, authentication, association, DHCP or data — so no client can connect, hand over a credential or be relayed. Reports how to verify the alert | requires root + `--transmit --authorized --yes` |

Every kick mode refuses broadcast/multicast or wildcard `--client`/`--bssid`
(kicking *all* clients is an attack, not a test), never loops, and logs each
frame with direction/reason to the 0600 audit CSV. Disassociation is the
polite cousin of deauth (it asks an associated STA to drop the association);
both are management frames protected by PMF/802.11w, so a client that stays
associated has MFP correctly enforced.

Typical use: `inject --mode ids-selftest` in CI; then on your own lab AP
`sudo wifiscanner inject --mode pmf-test -i wlan0 -c 6 --bssid MY-AP-MAC
--client MY-LAPTOP-MAC --transmit --authorized --yes` — exit 0 = PMF
protected, 1 = client was kicked (fix 802.11w), 3 = inconclusive. The same
verdict applies to `--mode deauth --frame-type both`, which additionally
exercises the full deauth/disassoc path at a configurable (capped) burst size.

### `lab` — captive-portal phishing awareness lab (training simulation)

A **fully local** teaching rig for the "evil captive portal" lesson. Running
`wifiscanner lab` starts a small server (localhost by default, zero extra
dependencies) and prints two URLs:

* **Student portal** `http://localhost:8808/` — a realistic-looking Wi-Fi
  sign-in page pretending to be `--ssid` (default `CampusNet-Guest`),
  complete with captive-DNS behaviour (every unknown URL lands back on the
  login form). Students either use the printed **synthetic roster**
  (`traineeNN@lab.example` + generated passphrases — RFC 2606 domain, tied
  to no real service) or type whatever test credentials the exercise allows.
* **Instructor dashboard** `http://localhost:8808/i/<token>` — the token is
  random per run (fix it with `--instructor-token`) and the portal never
  links to it. It auto-refreshes and shows the **attack flow funnel**
  (portal views → unique clients → submissions → captured roster accounts →
  fastest view→submit time), the **captured TEST values** exactly as typed
  (this table *is* what a real attacker's log would contain), per-account
  roster status, a timestamped **detection event log**, and a **Reset**
  button that wipes submissions/events between exercises.

Flow: a submission goes to `/submit`, is recorded with verdict
`roster-match` / `roster-account-wrong-secret` / `off-roster` in the
owner-only (0600) SQLite training DB (`--db`), fires a `lab capture #N`
console line plus a `credential-submit` event (the detection/logging part),
and lands the student on an instant **debrief page**. Linked from there:

* `/indicators` — seven tells that expose the fake portal (no HTTPS padlock,
  bare-IP host, uninvited appearance, template branding, over-asking,
  pressure language, no out-of-band verification), two hidden
  `view-source:` markers to hunt, and pointers to the RF side
  (`ids`, `ids --learn`, `scan` rogue rows, `inject --mode ids-selftest`).
* `/compare` — legitimate reference portal (`/legit`) vs the simulated
  phishing portal, side by side: address bar, transport, arrival path,
  branding, data requested, verifiability.
* `/learn` — the attacker's view: the full kill chain (deauth kick → evil
  twin → captive DNS → fake portal → captured credentials → reuse), what one
  submission hands over (password verbatim, account enumeration, IP, UA
  fingerprint, timestamps), and the defender's checklist.

Hard scope rules, enforced in code: nothing in `lab` performs RF work,
clones an AP, intercepts DNS, decrypts, or contacts any real authentication
system; the only "valid" credentials that can ever exist are the synthetic
roster entries. Everything else is `--bind`/`--port` (default
`127.0.0.1:8808`; `--bind 0.0.0.0` for a classroom LAN you control),
`--duration N` auto-stop, `-o DIR` to export `lab_accounts.csv` /
`lab_attempts.csv` / `lab_events.csv` / `lab.json` (0600) on exit, and:

```
wifiscanner lab --self-test    # 12-check offline proof, no port stays open
wifiscanner lab --reset --yes                     # wipe submissions (roster kept)
wifiscanner lab --reset --yes --rotate-roster     # + fresh synthetic credentials
```

### `wpa-lab` — WPA/WPA2/WPA3 decryption laboratory

An offline, hands-on crypto lesson built on **real laboratory captures and
real verified cryptography** — not a simulation of one. Six actions:

```
wifiscanner wpa-lab make-fixture lesson.pcap --ssid ClassNet-7 \
    --password 'lab-secret-99!'      # instructor: build the lab capture
wifiscanner wpa-lab inventory lesson.pcap        # ex.1: frame/handshake map
wifiscanner wpa-lab try lesson.pcap --ssid ClassNet-7 --password wrong
                                                 # ex.2: watch the MIC reject it
wifiscanner wpa-lab try lesson.pcap --ssid ClassNet-7 --password 'lab-secret-99!'
                                                 # ex.3: verify + decrypt
wifiscanner wpa-lab decrypt lesson.pcap --ssid ClassNet-7 \
    --password 'lab-secret-99!' -o out           # full export bundle
wifiscanner wpa-lab web lesson.pcap --ssid ClassNet-7 --password '...'
                                                 # student + instructor web UI
wifiscanner wpa-lab exercises                    # the guided worksheet
```

Under the hood, sharing the lab's capture format with any real 802.11
monitor capture (`wifiscanner capture`, tcpdump `-I`, Wireshark dumps;
Radiotap or raw 802.11 pcaps):

* **pipelines**: stdlib pcap reader → 802.11 dissection (DS flags, QoS/TID,
  protected bit, seq) → RSN/WPA IE parsing → generation labels
  (WPA / WPA2 / WPA2-Ent / WPA3-SAE / transition / OPEN) → EAPOL-Key
  message classification (M1–M4, nonces, replay counters, MIC, encrypted
  key data).
* **authorised decryption**: `LabKey` accepts a passphrase (+SSID → PBKDF2
  PMK), a raw 64-hex PSK, or a raw PMK (`--pmk` — the path for WPA3-SAE
  captures, where SAE removes the offline passphrase equivalence).
  `derive_ptk` builds KCK/KEK/TK with the 802.11 PRF; the candidate is
  verified by recomputing the message-2/4 MIC before any data frame is
  touched. Verified sessions decrypt CCMP-128/CCMP-256 (AES-CCM) and
  GCMP (AES-GCM) data frames; the GTK is recovered from the KEK-wrapped
  (AES-KWP, RFC 5649) message-3 key data so broadcast/multicast frames
  (ARP etc.) decrypt too.
* **before vs after**: without a key, rows carry only MACs/sizes/timing;
  after, the summariser spells out IPv4 flows — ARP requests, DNS names,
  HTTP request lines and response bodies, ICMP. `decrypt -o DIR` writes
  `wpa_lab_frames.csv`, `wpa_lab_decrypted.pcap` (Ethernet — drop straight
  into Wireshark, exercise 6), `wpa_lab.json` and `wpa_lab_report.md`
  (owner-only 0600).
* **failure cases are the curriculum**: wrong key → MIC mismatch
  (`try` exits 1); capture without a handshake → even the correct key
  cannot form a PTK (`try` exits 3 with the teaching note);
  incomplete handshake (M1 only) → explicit `no-handshake` verdict;
  corrupt/truncated frames → `decrypt-failed` rows. TKIP bodies are
  detected and *explained*, not decrypted (its design flaws are the
  lesson); WPA3 SAE exchanges are detected and annotated, with `--pmk`
  as the authorised decryption path.
* **crypto trust**: every primitive is verified in the test suite against
  published vectors — AES-128/192/256 (FIPS-197), CCM (RFC 3610), GCM
  (NIST), CMAC (RFC 4493), KW (RFC 3394), RC4, PBKDF2/PMK (RFC 6070 plus
  the canonical `password`/`IEEE` 802.11 vector). No `pip install` needed.
* **web mode** (`wpa-lab web`): student portal at `/` (capture facts, key
  submission with MIC-verified result pages, before/after frame list,
  guided exercise sheet) and a token-gated instructor dashboard at
  `/i/<token>` (page-view/key-attempt detection log, funnel, one-click
  authorised decrypt with the loaded lab keys, session reset). Attempts
  persist to a 0600 SQLite DB (`--db`, `:memory:` to opt out). Binds
  localhost by default; `--bind 0.0.0.0` for a classroom LAN you control.

### `mac-lab` — MAC randomization & deanonymization laboratory

An offline, instructor-controlled laboratory for the question *"if my phone
rotates its address, can anyone tell it's still me?"* — answered with a
synthetic multi-sensor dataset and an evidence engine whose reasoning is
**fully exposed** (support, anti-evidence, graduated confidence, and the
trap that proves why fingerprint ≠ identity). Seven actions:

```
wifiscanner mac-lab make-dataset macds --seed 8 --fresh
                                          # instructor: build the dataset
wifiscanner mac-lab inventory macds       # every observed MAC: type,
                                          #   fingerprint, probed SSIDs
wifiscanner mac-lab correlate macds       # pairwise evidence matrix +
                                          #   engine clusters (hypotheses)
wifiscanner mac-lab explain macds M1 M2   # full reasoning for one pair
cat answer.json | wifiscanner mac-lab score macds --submit -
wifiscanner mac-lab web macds             # student portal + instructor dash
wifiscanner mac-lab exercises             # the guided worksheet
```

* **dataset**: `make-dataset` writes `sensor-<name>.pcap` files (Radiotap,
  probe-requests only), a `manifest.json`, and an instructor-only
  `ground-truth.csv` (0600, never rendered to students). The scenario: a
  phone rotating between three randomized MACs with same-day hand-off
  chains (30–150 s), two **twin decoys** sharing fingerprint *and* probed
  SSID sets but visible simultaneously at different sensors, a stable
  laptop control, a cadence-telling IoT badge, and grey-zone background.
* **correlation engine**: +40 identical IE fingerprint · +25×Jaccard on
  probed SSIDs · +15 session-in/silence-out rotation hand-off (2 s..180 s)
  · +5 RSSI proximity · +5 cadence · +5 both-randomized — versus hard
  anti-evidence (−70/−100 simultaneous presence ⇒ provably distinct).
  A fingerprint-only match can **never** climb past `possible` (same-model
  coincidence); every verdict is a labelled hypothesis
  (`low / possible / likely / high / different`) with named caveats.
* **scoring**: correct merges earn, wrong merges cost, and merging the
  twins explicitly triggers the twin-trap feedback (simultaneous presence
  is proof of two devices). Success and failure walks are equally real.
* **web mode**: student pages (MAC roster, evidence matrix, clustering
  quiz, worksheet) + token-gated instructor dashboard (`/i/<token>`, ground
  truth table, detection-log of attempts, funnel, reset, and **one-click
  🎲 regenerate** which rebuilds a fresh dataset with `seed+1` in place).

### `track-lab` — long-term device tracking & privacy laboratory

Two weeks of synthetic sightings answer *"how much can a collector learn
from a persistent identifier + time?"* — and *"what breaks it?"*:

```
wifiscanner track-lab make-dataset tds --seed 9 --fresh   # instructor
wifiscanner track-lab inventory tds      # who is most present? visits/days
wifiscanner track-lab history tds --mac 3C:5A:B4:71:00:42
wifiscanner track-lab patterns tds --mac 3C:5A:B4:71:00:42
                                         # hour heatmap, weekdays, dwell,
                                         # movement edges + trackability
wifiscanner track-lab compare tds --since 2d
                                         # short window vs full retention
wifiscanner track-lab score tds --answers quiz.json
wifiscanner track-lab web tds --port 8822
wifiscanner track-lab exercises
```

* **scenario**: Student-A keeps a predictable weekday routine
  (`lab-north → canteen → lab-south`); Decoy-A′ shares Student-A's OUI and
  morning window but lives in the corridor only (the false-positive trap);
  Visitor-B rotates a fresh MAC every single visit — the privacy defence,
  watched *working*; Staff-IoT badges a fixed daily loop; ~100 one-shot
  background devices fill the grey zone. All synthetic; lab grid only.
* **engine**: visit sessionization (3-min gap split), per-MAC weekday/hour
  heatmaps, dwell minutes per sensor, movement edges (same-day transitions
  ≤6 h), and a plain-words trackability verdict keyed on persistence.
* **the retention lesson**: `compare --since 2d` shows the 2-day window
  supports presence only — the same database with a longer retention
  reconstructs the routine. The dataset didn't change; *retention* did.
* **quiz + traps**: scoring credits the correct identity and punishes the
  same-OUI decoy attribution with the specific rule it violates
  (`Same-OUI ≠ same owner`). `web` mirrors everything with a student
  portal and instructor dashboard (ground truth, attempt log, one-click
  reset **and dataset regeneration**).

### `stealth-lab` — hidden monitoring & stealth detection laboratory

The question is *"how would you even notice a monitor that hides?"*
The lab synthesises four days of host telemetry for `lab-ws-07` — process
snapshots, connection tables, file events, service registry, auth.log — and
hides an implant inside. Students get exactly what a normal administrator
sees at any chosen tick; an instructor console advances time.

```
wifiscanner stealth-lab make-scenario scn --seed 10 --fresh  # instructor
wifiscanner stealth-lab telemetry scn --kind procs --day 3
wifiscanner stealth-lab hunt scn          # league of suspects + signals
wifiscanner stealth-lab explain scn IMPLANT
wifiscanner stealth-lab compare scn       # authorised vs covert monitor
wifiscanner stealth-lab alerts scn        # normal → suspicious transitions
wifiscanner stealth-lab score scn --answers ans.json
wifiscanner stealth-lab web scn --port 8823
```

* **beats** (seeded, deterministic): install → 6-hourly keepalives → the
  night **flip** (cadence tightens ~40×, CPU spikes 22:00–06:00) →
  **concealment** (process vanishes from ps while sockets keep flowing —
  the ps-vs-ss discrepancy, plus an auth.log black hole over its active
  window) → **respawn/rename** on the same C2 → **unlink-while-running**
  of the staging file (`ls` sees nothing; the fd does).
* **signals are first-class**: name-mimicry (40), unowned package (15),
  concealment (60), C2 egress (25), cadence flip (20), night delta (20),
  respawn (15), hidden staging (10), unlink (30), audit gap (20). The IT
  monitor is course-provided and *must not* be shot — the false-accusation
  branch is scored.
* **visibility table** on the home page makes explicit which instrument
  stealth can blind and which one betrays it.

### `response-lab` — automatic (offensive) response laboratory

An IDS event stream (deterministic per seed) hits **designated lab test
devices**: a deauth flood, a port sweep, an auth brute-force, then low-exfil
beacons from `TEST-ATTACK-01`; scheduled sweeps from the organisation's
own `IT-SCAN-01`; ambient below-threshold chatter from `NEIGHBOR-77`.
Policies R1–R5 record/alert/block; **R6 (aggressive) ships disabled**.

```
wifiscanner response-lab cast                     # designated devices
wifiscanner response-lab rules                    # the rulebook
wifiscanner response-lab simulate --mode dry-run  # what WOULD happen
wifiscanner response-lab simulate --mode auto
wifiscanner response-lab simulate --mode auto --enable-rule R6 \
    --clear-allowlist                             # friendly fire, on purpose
wifiscanner response-lab simulate --mode approval
wifiscanner response-lab score --answers ans.json
wifiscanner response-lab web --port 8824          # portal + console
```

* **modes**: `dry-run` logs decisions and `would-block` results without
  touching state (and never consumes history); `approval` queues actions
  for an instructor click (approve/deny); `auto` executes into the
  simulated firewall table immediately; `manual` records only.
* **false-positive engineering**: enable R6 with an empty allowlist and the
  lab blocks its own IT scanner at tick 4. Reinstate the allowlist, roll
  the block back, re-run — the audit makes the before/after obvious.
* **safety scope**: responses act ONLY on registered lab devices; every
  other source is answered `out-of-scope` at decision time. The firewall
  is a dict in this process — nothing real is ever touched.
* **auditability**: every action leaves a detect → decision → response →
  result chain, and every rollback its own entry. Manual vs auto runtimes,
  the helper block you must not write, and the approval choreography are
  the worksheet exercises.

### `handshake-lab` — WPA handshake capture & password-auditing laboratory

`handshake-lab` teaches, with real cryptographic operations, why Wi-Fi
password strength matters.  The instructor generates a dataset of lab
captures (4-way handshakes plus a small encrypted tail, all over the
lab-only SSID `LabHS3-Intro` and the `02:1a:c3` MAC block — nothing is
transmitted or observed) and three difficulty tiers of lab-minted
wordlists.  Students validate the capture, run an offline MIC-driven
dictionary audit with measured timing and guess rates, and finish by
*authenticating* — proving knowledge of the credential by decrypting a
post-handshake frame.  The easy and medium tiers fall quickly; the
expert tier's strong credential is not in the list at all, so the audit
exhausts: that failure is the intended lesson.  Quiz + exercises +
scoring; instructor console (:8829) rotates credentials/captures, resets
progress, or destroys the dataset outright.

```
wifi-scanner handshake-lab make-dataset /tmp/hs --seed 3 --fresh
wifi-scanner handshake-lab inventory --db /tmp/hs
wifi-scanner handshake-lab analyze --db /tmp/hs --tier easy
wifi-scanner handshake-lab audit --db /tmp/hs --tier easy       # found fast
wifi-scanner handshake-lab audit --db /tmp/hs --tier expert     # resists
wifi-scanner handshake-lab compare --db /tmp/hs                 # three tiers
wifi-scanner handshake-lab authenticate --db /tmp/hs --tier easy \
    --password coffee-shop
wifi-scanner handshake-lab web --db /tmp/hs --instructor-token tok
```

### `priv-lab` — wireless privacy & MAC-randomization laboratory

`priv-lab` teaches where MAC randomization actually ends.  An
instructor-generated dataset of *synthetic* observations (every MAC sits
in the locally-administered `02:1a:b4` block — no real radio or vendor
identity is involved) is loaded into a web console (`:8827`) where
students see raw probe logs, run the correlation engine, and learn that
identical probe-request fingerprints and daily routines re-cluster
rotated MACs anyway.  The privacy page quantifies PNO-list leakage
before/after a scrub, the what-if simulator scores configuration knobs,
and a scope sentinel refuses — with a logged alert — any attempt to
correlate the lab's reference AP.

```
wifi-scanner priv-lab make-dataset /tmp/priv --seed 14 --devices 10 --fresh
wifi-scanner priv-lab inventory --db /tmp/priv
wifi-scanner priv-lab correlate --db /tmp/priv        # clusters + confidence
wifi-scanner priv-lab correlate --db /tmp/priv --target LAB-DEV-01
                                                     # refused (scope)
wifi-scanner priv-lab compare --db /tmp/priv          # scrub before/after
wifi-scanner priv-lab score --answers answers.json
wifi-scanner priv-lab web --db /tmp/priv --instructor-token tok
```

### `rf-lab` — RF interference & Wi-Fi resilience laboratory

`rf-lab` is a simulation-only interference lab: a deterministic engine
models channel utilisation, SNR, loss, latency and goodput for three lab
APs on channels 1/6/11.  The instructor starts one of four interferer
profiles (microwave, Bluetooth hopper, 2.4 GHz cordless, wideband chaos)
at a hard-capped intensity, students watch sparklines degrade, run the
detector (which classifies the interferer from its signature as a
passive monitor would), compare before/after reports, and pass the
resilience exercise by re-channeling the hit AP onto a non-overlapping
quiet channel.  No RF is emitted — the lesson is in the numbers.

```
wifi-scanner rf-lab baseline                          # healthy estate
wifi-scanner rf-lab inject --interferer microwave --intensity 70
wifi-scanner rf-lab compare --interferer cordless --intensity 90
wifi-scanner rf-lab investigate --interferer bluetooth --intensity 80
wifi-scanner rf-lab resilience --ap LAB-AP-3 --channel 1
wifi-scanner rf-lab web --instructor-token tok        # console :8828
```

### `scan-lab` — large-scale scanning & scope-control laboratory

`scan-lab` is an instructor-controlled scanning lab against a *virtual*
estate: generated inventory on `10.77.*` (services, online flags,
duplicate-IP conflicts), a simulated scan engine with real concurrency +
rate limiting and per-job progress, and a scope sentinel that refuses
unlisted or out-of-subnet targets **before probing** and raises a visible
alert on every attempt. Nothing on wire reaches anything real.

```
wifi-scanner scan-lab web --db /tmp/estate           # console :8825
wifi-scanner scan-lab make-dataset /tmp/estate --seed 12 --size 80
wifi-scanner scan-lab inventory --db /tmp/estate     # census + duplicate IPs
wifi-scanner scan-lab scan --db /tmp/estate \
    --targets '[10.77.0.*,192.168.1.1]'              # out-of-scope refused
wifi-scanner scan-lab compare --db /tmp/estate       # targeted vs sweep
wifi-scanner scan-lab score --answers ...
```

On the web console: run jobs from the form, watch live progress + scope
refusals, export CSV, take the scored quiz; the instructor page
(`/i/<token>`) offers estate expand, full reset and regenerate.

### `cred-lab` — credential & session security laboratory

`cred-lab` uses a lab-generated capture that contains both versions of
the same synthetic day: six plaintext auth surfaces (HTTP Basic via
base64, form POST, FTP USER/PASS, Telnet keystrokes, SNMPv1 community
strings, replayable session cookies) dissected and counted — and the
same identities over TLS where only SNI survives. Every identity is
lab-minted (`LAB-STUDENT-*`); the instructor can rotate or destroy them.

```
wifi-scanner cred-lab make-fixture /tmp/lesson.pcap --students 6
wifi-scanner cred-lab dissect  /tmp/lesson.pcap      # census + exposure count
wifi-scanner cred-lab exposures /tmp/lesson.pcap     # plaintext table
wifi-scanner cred-lab tls /tmp/lesson.pcap           # what TLS hides
wifi-scanner cred-lab alerts /tmp/lesson.pcap        # insecure-auth findings
wifi-scanner cred-lab report /tmp/lesson.pcap -o /tmp/bundle
wifi-scanner cred-lab web /tmp/lesson.pcap --instructor-token tok
```

### `db` — history-database maintenance (privacy controls)
`--report` (permissions/size/retention/table counts + world-readable warning),
`--prune-days N` (delete old rows + vacuum), `--delete-mac AA:..` (erase one
device everywhere, MAC or pseudonym), `--anonymize-db --yes` (**irreversible**:
salted MAC pseudonyms, IPs/hostnames wiped), `--purge --yes` (delete all history,
keep warden baseline), `--vacuum`. Destructive actions require `--yes`.

### `interfaces` — capability report
platform, root?, backends found, scapy present?, OUI table size, and each
wireless interface with mode / MAC / channel.

---

## 9. Output artefacts

All files UTF-8 **with BOM** (opens correctly in Excel), RFC-4180 quoting,
header row always present, filenames `wifi-<scanid>_*` (or your `--prefix`).
Every row carries `scan_id` so repeated scans concatenate in pandas.

All exports are written owner-only (0600); pass `--anonymize` for salted,
per-export, unlinkable MAC pseudonyms with hostnames/IPs/probes dropped.

### `<prefix>_networks.csv` — 49 columns, one row per BSS

| Column | Meaning |
|---|---|
| `scan_id` | run id (UTC-stamped) |
| `bssid` `ssid` `hidden` | identity; `hidden=1` = beacon/probe had no SSID |
| `vendor` | OUI vendor of the BSSID |
| `band` `channel` `frequency_mhz` `channel_width_mhz` | RF position (20/40/80/160 from HT/VHT/HE IEs) |
| `rssi_dbm` `rssi_min_dbm` `rssi_max_dbm` `noise_dbm` `snr_db` | signal levels over the whole run |
| `signal_quality_pct` `signal_bars` `estimated_distance_m` | derived quality + path-loss distance (§11.3) |
| `encryption` `ciphers` `auth_suites` `pmf` | security stack from RSN/WPA IEs (`pmf`: required/optional/disabled) |
| `wps` | WPS IE advertised |
| `security_score` `security_grade` `risks` | 0–100 / A+…F / `;`-joined risk codes (§11.2) |
| `phy_modes` `max_rate_mbps` | 802.11 a/b/g/n/ac/ax/be + top basic rate |
| `beacon_interval_tu` `dtim_period` `country` `mesh` | beacon internals |
| `beacons_seen` `data_packets` | frames attributed during capture (monitor mode only) |
| `connected_devices` `active_devices` `client_macs` | device count (§3), clients with ≥1 data frame, `|`-joined MACs |
| `bss_load_sta_count` `channel_utilization_pct` | BSS Load IE (element 11) — the AP's *own* claim |
| `eapol_frames` `deauth_frames` | handshake joins and deauth activity seen (feeds `ids` too) |
| `first_seen` `last_seen` `source` | wall-clock bounds; sources merged, e.g. `iw+monitor+lan` |

### `<prefix>_devices.csv` — 23 columns, one row per client

`scan_id`, `mac`, `vendor`, `is_randomized` (locally-administered → privacy
MAC), `associated_bssid`, `associated_ssid`, `ip_address`, `hostname`,
`open_ports` (own-LAN enrichment only), `rssi_dbm` (+min/max),
`signal_quality_pct`, `estimated_distance_m`, `channel`, `packets`,
`data_packets`, `bytes_seen`, `dwell_s` (first→last observation span),
`probed_ssids` (`,`-joined; unassociated devices only), `state`
(`associated` / `unassociated/probing` in the CSV; the DB additionally
keeps `lan` rows), `first_seen`, `last_seen`.

### Also

| File | Contents |
|---|---|
| `*_channels.csv` | per band: channel, ap_count, overlapping_aps (2.4 GHz ±4 modelling), total_interferers, clients, strongest_rssi, SSIDs |
| `*_rogue_alerts.csv` | SSID, bssid_count, bssids, severity, reasons (§11.4) |
| `*_summary.csv` | scan-level metrics (`metric,value`) |
| `presence_sessions.csv` | `presence -o`: mac, bssid, ssid, first/last_seen, duration_s, sightings, avg/min/max_rssi |
| `trail-<MAC>.csv` | ts, time, x, y, unc_m, error_radius_m, zone, zone_confidence, method, confidence, sensor_count, display |
| `traffic_events.csv` | time, ts, src/dst_mac, src, dst, proto, summary, detail, alert (redacted by default) |
| `traffic_flows.csv` | src, dst, proto, packets, bytes, bytes_h, first, last, notes |
| `ids_alerts.csv` | time, severity, kind, bssid, ssid, src, dst, confidence, confidence_label, status, evidence, detail |
| `audit_report.md` | checkbox list per BSS: `[x]/[!]/[ ]` |
| `<prefix>.json` | everything nested: `{scan_id, generated_at, summary, connection, networks[], devices[], channel_congestion{band:[]}, rogue_alerts[]}` |
| `<prefix>.html` | standalone dark-theme dashboard: summary cards, rogue banner, AP table (signal bars, grade pills), device table, channel bars, recommended channels |
| `<prefix>.md` | quick notes: summary bullets, rogue alerts, AP table |

---

## 10. SQLite history schema & queries

`Store` (WAL mode — read while recording). Tables:

```sql
scans(scan_id PK, ts, duration, mode, sensor, networks, devices, meta)
  mode: scan|monitor|full|devices|offline|own|record|locate-live|pcap-import
networks(scan_id, ts, sensor, bssid, ssid, channel, band, rssi, security, grade, clients)
devices(scan_id, ts, sensor, mac, bssid, ssid, state, rssi, packets, data,
        bytes, ip, hostname, randomized, probed)
observations(ts, sensor, mac, bssid, rssi, freq)   -- raw feeds for locate
fixes(ts, mac, x, y, unc, method, sensors)         -- computed positions
warden(bssid PK, ssid, meta, first_seen, last_seen, seen)
```

Indexed: `devices(mac,ts)`, `devices(ssid,ts)`, `observations(mac,ts)`,
`fixes(mac,ts)`.

The CLI covers the usual questions; anything else is plain SQL, e.g.:

```bash
sqlite3 home.sqlite "SELECT ssid, COUNT(DISTINCT mac) FROM devices
  WHERE ts > strftime('%s','now','-7 days') GROUP BY ssid;"
sqlite3 home.sqlite "SELECT mac, MAX(ts) FROM devices GROUP BY mac;"
```

Retention: `Store.prune(days)` is exposed in the API (`--keep-days` CLI flag
is intentionally absent — prune deliberately, knowing history is the point).

**Session semantics** (`presence`): rows for (mac, bssid) within `--gap`
seconds collapse into one session; a longer silence or an AP change starts a
new one. `state IN ('associated','lan')` rows only — probe requests are never
persisted.

---

## 11. Methodology

### 11.1 Source merge (engine)
Keyed by BSSID, richer-wins: first non-empty SSID wins (hidden→named
promotes), channel/freq/country/DTIM etc. fill if missing, RSSI keeps max
(+running min/max), security union minus `OPEN` when anything real exists,
PHY/ciphers/AKMs union, flags OR'd, counters summed, time bounds merged,
clients merged by MAC, sources recorded as `iw+monitor+lan`.

### 11.2 Security score & grade (models.py — exact arithmetic)
Base: OPEN/none 5 · WEP 15 · WPA-only 35 · WPA2 70 · WPA2+WPA3 transition 80
· WPA3-only 100. Modifiers: WPS −25 (Pixie-Dust/PIN exposure) · TKIP −15 ·
PMF required +5 · PMF disabled/unknown −5. Clamp 0–100.
Grade: ≥90 `A+` · ≥80 `A` · ≥70 `B` · ≥55 `C` · ≥35 `D` · else `F`.
Risk codes: `open-network:traffic-in-cleartext`, `wep:trivially-crackable`,
`wpa1-legacy`, `tkip-cipher-deprecated`, `wps-enabled:pixie-dust`,
`no-pmf:deauth-possible`, `hidden-ssid:security-by-obscurity`,
`very-close-transmitter` (RSSI > −35).

### 11.3 RSSI → quality → distance
`quality%` = Microsoft linear map (−100→0, −50→100). Bars: 4-block glyph.
Distance (and `locate` ranging) invert the log-distance model:

```
FSPL₁ₘ(f) = 20·log10(f_MHz) − 27.55
d = 10 ^ ((Tx − FSPL₁ₘ − (RSSI + sensor_offset)) / (10·n))
Tx default 20 dBm · n default 2.7 (2.0 free space, 3.5 dense indoor)
```
Clamped 0.1–2000 m for the survey column; `locate` ranges clamp 0.2–500 m.
**Order-of-magnitude only** — walls/antenna gain move
it; that's why `locate` reports per-fix uncertainty instead of hiding it.

### 11.4 Rogue / evil-twin scoring (multi-indicator)
Per SSID with ≥2 BSSIDs, each independent indicator scores evidence —
`open-clone` 45, `security-mismatch` 25, `vendor-mismatch` 20,
`warden-unknown` 20, `pmf-mismatch` 15, `signal-anomaly` 10, `channel-anomaly` 10 —
fused with noisy-OR into `score` 0-100. Verdict `likely-rogue` requires **≥2
indicators AND score ≥ 40** (severity `high` for open clones, else `medium`);
single-indicator groups are listed as `unconfirmed` (severity `low`) and never
counted as rogue — extenders, mesh nodes and multi-vendor enterprise WLANs all
produce single-indicator lookalikes. Warden adds: any beacon whose BSSID isn't in
`warden` table → `unknown-bss`; any beacon whose (channel, security-IE set) changed
mid-run → `beacon-mutation` (low confidence until the new fingerprint persists).

### 11.5 Audit checks (each = weakness → attack → fix)
`WPA3 / PMF-required encryption` · `PMF (802.11w) protects management frames`
(no PMF ⇒ client-kick & reauth bait work) · `No WPS` · `No WEP/TKIP/RC4
anywhere` · `WPA2 uses AES-CCMP` (+ “strong passphrase” caveat, since WPA2-PSK
handshakes are offline-grindable — the fix is WPA3/SAE or a ≥25-char
passphrase, **not** cracking) · `Authentication present` (open BSS ⇒
`traffic` demonstrates the leak) · `No abnormal handshake churn during scan`
(≥20 EAPOL in one passive window ⇒ run `ids`).

### 11.6 MAC classification
`is_randomized`: bit 1 of first octet (locally administered) — iOS/Android
privacy addresses. `is_multicast`: bit 0 (broadcast frames never counted as
clients). Vendor lookup = 24-bit OUI prefix, built-in table +
`manuf`/`nmap` nsel files when present.

### 11.7 Client counting rules
A client counts for an AP when a data frame binds them (To-DS/From-DS), an
association request names that BSSID, or EAPOL flows on that BSS with that
MAC. Broadcast/multicast/NULL/QoS-no-data don't create clients. “Active” =
≥1 data packet. Duplicate MACs across APs are separate bindings.

---

## 12. Sensor-grid positioning guide

**Model:** 3+ fixed receivers (`record --sensor`) at surveyed positions;
each pass writes per-device RSSI rows with its tag; `locate` fuses readings
from different sensors that fall within `--window` seconds.

`sensors.csv` (metres on any consistent local grid; origin arbitrary):

```csv
name,x,y,floor,rssi_offset_db,tx_power_dbm
front-door,0,0,0,,4.0,-4        # this antenna reads 4 dB strong, wants −4 cal
living-room,8,2,0
kitchen,8,12,0
```

`zones.csv` — polygon vertices, one zone per consecutive block (order =
perimeter):

```csv
zone,x,y
living,0,0
living,10,0
living,10,10
living,0,10
kitchen,10,0
kitchen,20,0
kitchen,20,10
kitchen,10,10
```

Pipeline:

```bash
# each box:      record --db /srv/presence-$HOSTNAME.sqlite --sensor $HOSTNAME
#               (systemd unit in §14); merge files (same schema, one DB each —
#                easiest: copy rows with sqlite3 ATTACH, or point all
#                sensors at one shared file on a server)
python3 main.py locate --db merged.sqlite --sensors sensors.csv \
                       --zones zones.csv --recompute
python3 main.py trail  --db merged.sqlite --sensors sensors.csv \
                       --zones zones.csv --mac AC:BC:32:01:02:03 --map -o out/
```

Methods you'll see: `trilateration` (WLS over ≥3 sensors, uncertainty =
2×residual-RMS), `bilateration(ambiguous)` (2 sensors, the better of the
two circle intersections), `nearest-sensor`, and
`nearest-sensor(guarded)` — the **sanity guard**: any fix whose uncertainty
exceeds the grid diagonal or lands >0.6×diag outside the sensor bbox is
demoted, never printed as fantasy. 1 sensor ⇒ zone-granularity hint only.
Indoor reality: expect **room/zone-level** accuracy, metres not centimetres.

---

## 13. The IDS: signatures it detects

| Kind | Trigger (defaults) | Severity | What you're seeing |
|---|---|---|---|
| `deauth-flood` | ≥ `--flood` (5) deauth/disassoc to one BSSID within `--window` (10 s) | high (baselined) / info | someone kicking clients — bait for auto-rejoin tricks; PMF-required networks ignore forged frames |
| `forced-reauth` | Association from a client ≤ window after a deauth targeted it | **critical** | the kick actually *worked*; client is renegotiating on command |
| `handshake-harvest-signature` | deauth → assoc → **EAPOL** within window | **critical** | someone is provoking fresh 4-way handshakes — the capture-for-offline-grind pattern. Mitigation: SAE/WPA3 + PMF required; rotate no secrets mid-incident |
| `eapol-storm` | > flood count of EAPOL on one BSS | high | mass renegotiation; same family as above |
| `beacon-mutation` | same BSSID's (channel, security IE set) changes mid-run | medium | either your reconfig or a live impersonator tweaking its beacon |
| `unknown-bss` | beacon from a BSSID not in the warden baseline (`ids --db … --learn`) | medium | new/novel AP advertising (possibly your SSID) |
| *(from scan)* | `rogue/evil-twin` rows in `*_rogue_alerts.csv` | medium/high | same-SSID multi-vendor / open-clone heuristics |

Mechanics: per-`window` sliding counters per BSSID; per-(kind, BSSID)
30 s cooldown so a burst = one alert; `--follow` streams alerts live;
`-o` exports `ids_alerts.csv`. Live mode uses the same passive sniffer —
**the watchdog itself has no transmit path; "detection only" is
architectural, not rhetorical.** (The separate `inject` command can verify
that detection end-to-end, but it never shares state with the watchdog and
only emits the harmless canary/self-test frames documented in §8.)

---

## 14. Operational recipes

**24/7 own-network monitor on a Pi (the intended deployment):**

```ini
# /etc/systemd/system/wifi-presence.service
[Unit]
Description=Wi-Fi presence recorder (own network)
After=network-online.target

[Service]
WorkingDirectory=/opt/wifi_scener
ExecStart=/opt/wifi_scener/.venv/bin/python main.py record \
    --db /var/lib/wifi/presence.sqlite --sensor kitchen --lan --interval 30
Restart=always
User=root                     # monitor + station dump; drop to cap_net_raw when polished

[Install]
WantedBy=multi-user.target
```

**Capture-then-analyse split** (field box vs desk):

```bash
sudo python3 main.py capture -i wlan0mon -d 3600 -o field.pcap --rotate-mb 64
python3 main.py offline field.pcap -o out/            # full survey tables
python3 main.py ids --pcap field.pcap                 # attack triage
python3 main.py traffic field.pcap -o out/            # what leaked cleartext
python3 main.py frames field.pcap --limit 20          # learn what you captured
```

**Ring-buffer forensic snapshot** — last ~24 h always available, capped:

```bash
sudo python3 main.py capture -i wlan0 -d 864000 -o /var/pcap/loop.pcap \
     --ring-segments 96 --rotate-mb 32       # 96×32 MB ≈ 3 GB, never more
```

**History diffing in pandas:**

```python
import pandas as pd, glob
dev  = pd.concat(map(pd.read_csv, glob.glob("out/*_devices.csv")))
nets = pd.concat(map(pd.read_csv, glob.glob("out/*_networks.csv")))
# busiest hour per SSID:
dev.assign(h=pd.to_datetime(dev.last_seen).dt.hour) \
   .groupby(["associated_ssid","h"]).mac.nunique().unstack(fill_value=0)
# networks that got weaker over the week (join on bssid across scan_ids)
```

**Cron report:** `presence --db home.sqlite --since -24h -o reports/` daily;
email `reports/presence_sessions.csv`.

**Verify a new IDS sensor before trusting it** (deploy check / CI):

```bash
# 1) offline, no radio, no root - does THIS sensor's detection code fire?
wifiscanner inject --mode ids-selftest -o checks/    # exit 0 = 4/4 signatures

# 2) live coverage drill on YOUR own lab network - does the deployed radio
#    actually hear every channel you assigned it?
wifiscanner inject --mode canary -i wlan0mon --channels 1,6,11 --no-monitor-setup \
     --transmit --authorized
# then on each remote sensor:
#   wifiscanner ids -i wlan0mon --follow     # or grep the token in its pcap/log

# 3) does PMF actually protect your clients from deauth kicks?
sudo wifiscanner inject --mode pmf-test -i wlan0mon -c 6 --no-monitor-setup \
     --bssid AA:BB:CC:DD:EE:FF --client <your-test-laptop-MAC> \
     --transmit --authorized --yes
# exit 0 = forged deauths were IGNORED (PMF works); 1 = client was kicked
# (set Management Frame Protection to REQUIRED and re-test); 3 = inconclusive

# 4) explicit authorised deauth/disassociation pen-test of YOUR own client:
sudo wifiscanner inject --mode deauth -i wlan0mon -c 6 --no-monitor-setup \
     --bssid AA:BB:CC:DD:EE:FF --client <your-test-laptop-MAC> \
     --frame-type both --direction ap-to-sta --count 10 \
     --transmit --authorized --yes
# bounded one-shot unicast burst; reports "KICKED" (vulnerable -> enable
# 802.11w) or "PASS" (frames ignored). Broadcast targets are refused.

# 5) Evil-Twin detection drill - does your IDS catch a rogue AP beaconing
#    YOUR SSID? (beacon ONLY: it cannot serve clients or capture anything):
sudo wifiscanner inject --mode evil-twin -i wlan0mon -c 6 --no-monitor-setup \
     --ssid YourOwnSSID --security open --duration 30 \
     --transmit --authorized --yes
# then verify on the sensor:
#   wifiscanner ids --db warden.sqlite -i wlan0mon   -> unknown-bss alert
#   wifiscanner scan                                 -> clone in *_rogue_alerts.csv
```

---

## 15. Python API

```python
from wifiscanner import Engine, export_all
from wifiscanner.backends import survey, sniffer, lan

eng = Engine()
eng.ingest(survey.survey_networks(rescan=True))          # OS-level pass
with sniffer.MonitorMode("wlan0") as mon:                 # root
    sn = sniffer.MonitorSniffer(mon, channels=[1, 6, 11])
    sn.run(30)
    eng.ingest(sn.results()); eng.ingest_unassociated(sn.unassociated)
eng.ingest_lan(lan.lan_inventory())

print(eng.summary()); print(eng.rogue_candidates())
export_all(eng, "output", formats=("csv", "json", "html"))

from wifiscanner.defense import Watchdog, audit_engine
from wifiscanner.frames import annotate_pcap
wd = Watchdog(); ... sniffer loop: wd.feed(pkt)
for row in audit_engine(eng): print(row)
```

`Store` gives `record_engine / sessions / known_devices / get_observations /
record_fixes / learn_warden / prune`; `locate` exposes
`load_sensors/load_zones/Tracker/multilateration` for custom pipelines.

---

## 16. Testing

```bash
python3 tests/make_fixture.py         # builds tests/fixture.pcap (288 frames:
                                      # beacons w/ real RSN/WPS/BSS-load IEs,
                                      # assoc+data+LLC/SNAP-EAPOL per client,
                                      # probe storms, a 9-frame deauth burst,
                                      # 5 BSS incl. an evil twin)
python3 tests/test_wifiscanner.py     # core suite, no radio, no root
python3 tests/test_injection.py       # injection gates/builders/selftest
python3 tests/test_lab.py             # phishing-lab: roster/store/HTTP/API/reset
python3 tests/test_wpalab.py          # WPA lab: crypto vectors → decrypt → web
python3 tests/test_devlab.py          # mac-lab + track-lab: datasets,
                                      #  correlation engine, tracker, traps,
                                      #  scoring, both web UIs, CLI smoke
python3 tests/test_solabs.py          # stealth-lab: telemetry scenario,
                                      #  signal engine, concealment beats,
                                      #  quiz; response-lab: rules, modes
                                      #  (dry-run/approval/auto/manual),
                                      #  FP story, rollback, audit chain
python3 tests/test_biglabs.py         # scan-lab: estate, sentinel scope
                                      #  refusals, rate limit, concurrency,
                                      #  cancel, web; cred-lab: six
                                      #  plaintext protocols exposed,
                                      #  TLS leg proven opaque, web +
                                      #  identity regeneration
python3 tests/test_privrf.py          # priv-lab: rotation clustering,
                                      #  scope refusal, scrub impact,
                                      #  what-if config; rf-lab: 4
                                      #  interferers classified, non-
                                      #  overlap resilience, instructor
                                      #  caps/audit, web
python3 tests/test_hsaudit.py         # handshake-lab: real 4-way capture
                                      #  validation, tiered wordlists,
                                      #  audit timing, resist case,
                                      #  three-state distinction, web +
                                      #  instructor regen/destroy
# => 246 tests total, all offline; nothing transmits in the test suite
```

The lab tests additionally cover: synthetic-roster determinism/domain/bounds;
LabStore verdict classification (`roster-match` / wrong-secret / off-roster),
funnel counters, dwell time, reset-keeps-roster and rotate-roster semantics;
the full HTTP path on an ephemeral loopback port (portal render, captive
redirect, submission → debrief without echoing the secret, instructor API
auth, dashboard stealth without the token, dashboard reset); POST size caps;
0600 owner-only export files; and CLI guards (`lab --reset` needs `--yes`,
`lab --self-test` passes 12/12).

Coverage: RF math round-trips; randomized/multicast MAC rules; OUI; score
ordering + WPS/TKIP penalties; station accounting idempotence; source merge
prefer-richer; dedupe; congestion & recommender; rogue/open-clone; summary
counts; canned `iw`/`netsh` parser fixtures; **pcap→client attribution
exact counts**; IE/RSN parsing; probe & deauth capture; **CSV schema
stability + Excel-safe quoting**; store round-trip + session gap-splitting +
time parsing; **trilateration ±1.2 m on synthetic grid**; bilateration;
zone geometry + dwell; sensor/zone file loaders; **IDS: flood threshold,
deauth→reassoc→EAPOL chain fires critical alerts, beacon mutation, warden
unknown-BSS**; audit rows PASS/FAIL logic; **frames annotator on real bytes
+ EAPOL flag decode + handshake census**; store warden; **traffic: DNS/HTTP
parse, credential alert with value redaction, ARP, SNI parser, protected
skip+count, 802.11 LLC/SNAP reassembly**; ring-buffer rotation on disk; CLI
smoke incl. `record` guardrail refusal and `traffic/ids/audit/frames/presence`
end-to-end subprocess runs; **trust: binding ranks, noisy-OR fusion, RF-vs-
confirmed census, identity ranges; rogue multi-indicator scoring + warden;
privacy: salted pseudonyms, redaction helpers, 0600 files; store retention/
erase/anonymize/ephemeral; IDS confidence + sensitivity + persistence +
adaptive margin; locate confidence + zone-primary display; capture `--ack`
refusal; `db` report/prune/destructive-guard; anonymized exports**; plus
**injection: probe/deauth frame bytes, LAA source-MAC generation, every
consent gate (root / --authorized / --yes) refusing the right way, broadcast-
target rejection, hard frame caps, dry-run emits zero frames while writing
the 0600 audit CSV, PMF pass/fail/inconclusive verdicts, canary matching, and
the offline IDS self-test detecting every signature end-to-end through the
CLI; disassociation-frame subtypes, the deauth/disassoc burst mode, both
directions, the one-shot kick cap, and a regression test that the IDS counts
disassoc floods (subtype 10) while never miscounting authentication frames
(subtype 11)**.

---

## 17. Platform support & limitations

| | Linux | macOS | Windows |
|---|---|---|---|
| Survey (`scan`/`detail`/`watch`) | ✅ iw/nmcli/iwlist | ✅ airport/system_profiler | ✅ netsh (needs Admin for profiles list) |
| Monitor capture (`monitor/capture/ids/traffic --live`) | ✅ with monitor-capable NIC | ⚠️ only cards already in monitor mode | ❌ driver stack |
| `own` via `iw station dump` (this box = AP) | ✅ | ❌ | ❌ |
| LAN sweep / `--ports` | ✅ | ✅ | ✅ |
| nmap acceleration | ✅ if installed | ✅ | ✅ |
| `traffic/frames/ids --pcap/offline` on captured files | ✅ | ✅ | ✅ |
| `record` history + `presence` | ✅ | ✅ | ✅ |
| `locate`/`trail` from multi-sensor DBs | ✅ | ✅ | ✅ |

Fundamental limits, stated plainly: encrypted payloads are never readable
(and never attacked); RSSI distance estimates are order-of-magnitude;
single-sensor setups cannot trilaterate; 2.4 GHz channel overlap modelling
assumes 20 MHz width; the OUI table ships trimmed — extend with
`/usr/share/nmap/nmap-mac-prefixes` or Wireshark's `manuf` when present.

---

## 18. Troubleshooting FAQ

| Symptom | Cause → fix |
|---|---|
| `backends: none` in `interfaces` | install `iw` (Linux) or be on a Wi-Fi-capable box; `netsh` needs Admin on Windows |
| `monitor mode requires root` | `sudo`, or `--no-monitor-setup` when the iface is already `wlanXmon` |
| Monitor setup fails `busy` | your managed connection holds the NIC — `nmcli device disconnect wlan0` first (auto-restored on exit) |
| Capture starts but 0 frames | NIC lacks monitor support (`iw list` → modes), or nothing on the channels hopped: `-c 1,6,11` to focus, check `dmesg` for firmware |
| `scapy required` messages | `pip install scapy` inside the venv you're running from |
| Colours/tables mangled | `NO_COLOR=1` forces the plain renderer; also fine for `>> log.txt` |
| `traffic` finds nothing | expected on encrypted nets — it only dissects cleartext, by design; use `ids` for attack triage and `offline` for client/AP structure |
| `record` refuses to start | no `--bssid` and not connected to Wi-Fi — point it at **your** AP explicitly |
| presence shows 0 sessions | gap larger than your scan interval? try `--gap 600`; or import a capture first: `record --pcap day.pcap` |
| locate: "no sensor observations" | history was recorded without `--sensor` tags, or sensor names don't match `sensors.csv` |
| Huge/nonsense x,y | you'll now see `nearest-sensor(guarded)` instead — check sensor coords & `--n-exp`, add calibration offsets |
| sqlite locked on shared NAS | WAL over NFS is unreliable — record locally, merge periodically |
| Windows Ctrl-C leaves `netsh` half-run | rerun `netsh wlan show interfaces` — cosmetic; no state is kept |

---

## 19. Legal & ethics

Everything here is scoped to infrastructure you own or explicitly authorise.
All survey/IDS/audit/history features are **receive-only**. Passive monitoring
of public airspace is permitted in most jurisdictions but not all, and
logging *people's* devices isn't the purpose of this tool (see §1 for what was
declined and why).

The single transmitting command (`inject`) follows the same rule a licensed
radio engineer follows when testing a network they operate: transmit only on
your own airspace, minimally, logged, and with explicit consent. The
deauth self-test briefly and reversibly disconnects **one device you name** if
PMF is off — that is an authorised, low-impact verification of a security
setting, the wireless equivalent of deliberately tripping your own fire
alarm to confirm the sensor works. It is never pointed at third parties:
broadcast targets and anything above the IDS flood threshold are refused in
code. You remain responsible for lawful, consented use in your jurisdiction.

If a design question is "could this harm a third party against their will?" —
that feature is not getting merged, here or in forks.

## 20. Changelog

* **v4.1.0** — **`handshake-lab`**: a WPA handshake capture &
  password-auditing laboratory. The instructor generates *real* 4-way
  handshakes (same vector-verified crypto as the decryptor) for a lab
  SSID on the lab-only MAC block, plus tiered lab wordlists
  (easy=weak-at-top, medium=weak-buried, expert=strong-outside-list).
  `analyze` proves capture validity; `audit` runs offline MIC checks
  over the instructor's wordlist with live timing (verified: easy found
  in 0.04 s, expert exhausts 420 candidates and *resists*);
  `authenticate` closes the loop by decrypting a post-handshake frame —
  the pedagogical CAPTURED≠AUDITED≠AUTHENTICATED distinction. Web
  console on :8829, instructor regenerate/reset/destroy, quiz 100/0.
  **246 tests**.
* **v4.0.0** — two more offline, instructor-controlled laboratories:
  **`priv-lab`** (wireless privacy & MAC randomization) — every
  identifier is synthetic; the engine clusters rotated MACs into identity
  tracks from probe-request fingerprints, routines and RSSI trends, the
  privacy page quantifies how a PNO-list scrub collapses leakage
  (349→0 SSIDs in the demo), a what-if simulator scores config knobs
  (scrub + IE randomize + irregular timing → confidence 0.10), and a
  scope sentinel refuses any correlation against the lab's own reference
  AP with loud, logged alerts; **`rf-lab`** (RF interference &
  resilience) — a deterministic metric engine models channel utilisation,
  SNR, loss, latency and throughput for three lab APs on channels
  1/6/11; the instructor starts/stops/resets/caps four interferer
  profiles, the passive-monitor detector classifies each from its
  signature, the compare command proves before/after deltas
  (ch11 −19.8% goodput under microwave@80 while ch1 stays flat), and the
  rechannel exercise moves the hit AP to a quiet channel with a
  measurable recovery score. No RF is generated or transmitted —
  everything is modelled. **232 tests**.
* **v3.0.0** — two more offline, instructor-controlled laboratories:
  **`scan-lab`** (large-scale scanning & scope control) — a virtual lab
  estate (instructor-generated, 10.77.* only), a simulated scan engine
  with real concurrency + rate limiting and a live progress chart, a scope
  sentinel that *refuses unlisted/out-of-subnet targets before probing*
  and alerts on every attempt, duplicate-IP inventory conflicts to find,
  targeted-vs-uncontrolled twin numbers, CSV results export, and an
  instructor console with expand/reset/regenerate; **`cred-lab`**
  (credential & session security) — one capture, two versions of the same
  day: six plaintext auth surfaces (HTTP Basic via base64, form POST, FTP
  USER/PASS, Telnet keystrokes, SNMPv1 community, replayable session
  cookies) dissected and counted, then the identical identities over TLS
  where only SNI survives; detector alerts for insecure-auth protocols, a
  report bundle (CSV+markdown), and rotate/destroy identity controls for
  the instructor. All credentials synthetic, all traffic lab-generated.
  **210 tests**.
* **v2.9.0** — two more offline, instructor-controlled laboratories:
  **`stealth-lab`** (hidden monitoring & stealth detection) — a seeded
  4-day host-telemetry scenario (process/connection/file/auth.log/service
  tables) with a concealed implant that installs, flips active at night,
  vanishes from ps (sockets keep talking — the ps-vs-ss lesson), wipes its
  auth.log window, respawns under a second kernel-lookalike name, and
  unlinks its staging file while running; an explainable signal engine
  (concealment 60 > name-mimic 40 > unlink 30 > cadence-flip 20 > …),
  behaviour-change alerts, a normal-vs-covert comparison page starring the
  authorised IT monitor students must NOT accuse, a scored five-finding
  hunt, and a token-gated instructor console with tick control + reset +
  regenerate; **`response-lab`** (automatic/offensive response) — a seeded
  IDS event stream aimed at designated lab test devices (deauth flood,
  port sweep, brute force, low-and-slow exfil), a rulebook (R1-R6; the
  aggressive R6 ships DISABLED), response modes dry-run / approval / auto /
  manual, a simulated firewall containing blocks, an instructor approval
  queue, first-class rollback, and a full detect->decide->respond->result
  audit trail with true/false-positive metrics (the friendly-fire trap:
  R6 + empty allowlist blocks your own IT scanner). Scope is enforced at
  decision time — policies always refuse non-designated sources.
  **188 tests**.
* **v2.8.0** — two more offline, instructor-controlled laboratories:
  **`mac-lab`** (MAC randomization & deanonymization) — an evidence engine
  that reasons out loud (+40 fingerprint · +25×Jaccard probed SSIDs · +15
  rotation hand-offs · RSSI/cadence/addr-type), hard anti-evidence for
  simultaneous presence (the twin decoys), a fingerprint-only cap so
  same-model coincidence can never look like identity, hypothesis-labelled
  clusters, a scored clustering exercise, and a token-gated web portal with
  instructor ground-truth dashboard and one-click **dataset regeneration**;
  **`track-lab`** (long-term device tracking) — visit sessionization,
  weekday/hour heatmaps, dwell, movement edges, trackability verdicts, the
  short-window-vs-full-retention contrast (`compare --since 2d`), a
  same-OUI decoy attribution trap scored as a false positive, a daily MAC
  rotator demonstrating the privacy defence working, and a privacy-brief
  page. Both labs: synthetic devices only, offline only, ground truth
  instructor-side (0600), attempts logged (SQLite 0600), and one-click
  reset/regenerate. **166 tests**.
* **v2.7.0** — `wpa-lab`: the **WPA/WPA2/WPA3 decryption laboratory**.
  Real capture pipeline (stdlib pcap/Radiotap/802.11/RSN/EAPOL parsing),
  offline key verification against the handshake MIC, and authorised
  decryption with laboratory key material: passphrase (PBKDF2), raw PSK,
  or raw PMK (the WPA3-SAE path). CCMP-128/256 and GCMP frame decryption,
  AES-KWP-wrapped GTK recovery so broadcast ARP decrypts too, before/after
  visibility reports, Ethernet `decrypted.pcap` export, failure cases as
  first-class output (wrong key = MIC mismatch, rc 1; missing handshake =
  rc 3 with the teaching note), a guided six-exercise worksheet, a
  `make-fixture` generator that emits cryptographically real lab captures
  (no radio required), and a token-gated student/instructor **web lab**
  with attempt detection logging and one-click authorised unlock. The
  crypto core is stdlib-only and pinned to published vectors (FIPS-197,
  RFC 3610/4493/3394, NIST GCM, RFC 6070 + the canonical 802.11 PMK
  vector). **143 tests**.
* **v2.6.0** — `lab`: a **captive-portal phishing AWARENESS lab**, fully
  local and RF-free. `wifiscanner lab` serves a realistic fake Wi-Fi login
  portal (captive redirect on unknown URLs included) plus a token-gated,
  auto-refreshing **instructor dashboard**: attack-flow funnel, captured
  TEST values, roster status, timestamped detection log, one-click reset.
  Training uses only a generated roster of synthetic accounts
  (`traineeNN@lab.example`); verdicts classify roster-match vs wrong-secret
  vs off-roster attempts; a submission triggers an instant debrief page and
  student-facing `/indicators`, `/compare` (legitimate vs phishing) and
  `/learn` (attacker's view + defender checklist) pages that cross-reference
  the IDS side for the RF hops. Everything persists to a 0600 SQLite
  training DB with `--reset --yes` / `--rotate-roster` cleanup and `-o`
  CSV/JSON export; `--self-test` proves all 12 lab checks offline. The
  binding default is localhost; nothing in `lab` transmits, clones an AP,
  harvests real credentials or contacts a real authentication service.
  **126 tests**.

* **v2.5.0** — Evil-Twin / rogue-AP *detection drill* (`inject --mode
  evil-twin`). Beacons a network name YOU own from a fresh spoofed BSSID for
  a hard-capped, self-terminating window (`--ssid`, `--security {open,wpa2}`,
  `-c`, `--duration`), gated behind root + `--transmit --authorized --yes`
  and fully audited. It is deliberately **beacon-only** — no probe-response,
  authentication, association, DHCP or data path — so it is visible as a fake
  AP yet cannot accept a client, capture a handshake/credential or relay
  traffic; it exists purely to verify that `ids` unknown-bss warden alerts
  and `scan` same-SSID/open-clone rogue heuristics fire. The drill is proven
  end-to-end to trip both detectors. There is no functional rogue AP,
  credential capture, karma or jamming in the codebase's RF path (v2.6.0's
  separate, loopback-only `lab` training simulation is documented in its
  own section above). **117 tests**.
* **v2.4.0** — full deauthentication/disassociation test + IDS subtype fix.
  `inject --mode deauth` sends a bounded, one-shot, **unicast** burst of
  deauth and/or disassociation frames (`--frame-type {deauth,disassoc,both}`,
  `--direction {ap-to-sta,sta-to-ap}`) at one client you own, gated behind
  root + `--transmit --authorized --yes`, hard-capped per run, and fully
  audited; reports whether the client was disconnected (enable 802.11w) or
  protected. **Fixed a real IDS bug:** disassociation frames are management
  subtype **10** but the watchdog matched `(12, 11)` — so disassociation
  floods were *missed* and authentication frames (subtype 11) were wrongly
  counted; the association branch also matched probe requests (subtype 4)
  instead of reassociations (subtype 2). Both now match the IEEE subtypes;
  the offline self-test adds a disassociation-flood signature. Dry runs
  remain the default and emit nothing. **110 tests**.
* **v2.3.0** — authorized packet injection for defensive self-test
  (`inject.py` + `inject` command): offline zero-RF IDS signature self-test
  (`--mode ids-selftest`, CI-safe); ordinary active probe scan; IDS/sensor
  coverage **canary** markers; bounded, unicast, own-AP **PMF / deauth
  resistance** test. Dry run by default; live emission gated behind root +
  `--transmit` + `--authorized` (+ `--yes` for deauth); hard per-mode frame
  caps below the IDS flood threshold; minimum inter-frame interval; broadcast
  and third-party targets refused; 0600 owner-only `injection_audit.csv` for
  every frame and a verification pcap. No flood, clone, jam or replay path.
  **101 tests**.
* **v2.2.0** — trust & privacy hardening (the 10 fixes, §21): central
  source+confidence trust model (`trust.py`); RF-observed vs router-confirmed
  census with per-binding evidence ranks; rotating-MAC honesty (observed-MAC
  ranges, never same/different-device claims); privacy modes
  (standard/minimal/ephemeral), salted MAC pseudonyms, auto-enforced retention,
  `db` maintenance (report/prune/erase/anonymize/purge/vacuum); zone-primary
  location with confidence + withheld low-confidence coordinates; capture
  acknowledgement (`--ack-sensitive`, warns-only), payload-stripping snaplen, 0600 secure storage
  everywhere; traffic redaction ON by default; IDS confidence/status/evidence,
  `--sensitivity`, beacon persistence, adaptive noisy-air margin; multi-indicator
  rogue scoring (≥2 indicators to declare). **76 tests**.
* **v2.1.0** — `ids` (7-detector passive watchdog + warden baseline),
  `audit` (weakness→attack→fix reports), `frames` (frame anatomy +
  handshake census); raw LLC/SNAP EAPOL detection; fixture rebuilt with
  realistic monitor-style EAPOL; **49 tests**.
* **v2.0.0** — `own`, `record`, `presence` (SQLite history, gap-aware
  sessions), `locate` (WLS trilateration + guard), `trail` (zones, dwell,
  ASCII maps), `capture` (streaming pcap, rotation, ring buffer),
  `traffic` (cleartext dissector, credential redaction); `--db` on all
  survey commands; own-network guardrails.
* **v1.0.0** — passive survey (5 OS backends), monitor-mode client
  attribution, RSN/IE parsing, security grading, rogue detection,
  congestion analysis, CSV×5/JSON/HTML/MD export, rich/ASCII terminal UI.
rk guardrails.
* **v1.0.0** — passive survey (5 OS backends), monitor-mode client
  attribution, RSN/IE parsing, security grading, rogue detection,
  congestion analysis, CSV×5/JSON/HTML/MD export, rich/ASCII terminal UI.

---

## 21. Trust & privacy model

v2.2.0 hardens the ten weaknesses below. The design principle throughout:
**every result carries its source and its confidence, and every byte written
to disk is minimised, permission-locked and retention-bounded.**

| # | Weakness | Fix (where) |
|---|---|---|
| 1 | Client counts stated as fact | `census`: `N✓ router-confirmed + M~ RF-observed` + 0-100 confidence; per-binding evidence ranks (`assoc-table` 98 … `single-frame` 35); router table **correlated**, never double-counted (`models.py`, `engine.py`, `backends/sniffer.py`) |
| 2 | Randomized MACs | `identity_report()`: observed-MAC ranges (min–max physical devices); `identity_note` disclaims **both** directions (distinct rotating addresses are neither distinct devices nor the same device); `oui.classify_mac()` (`models.py`, `engine.py`, `oui.py`) |
| 3 | Long-term tracking | `--privacy-mode standard/minimal/ephemeral`, `--anonymize` (salted HMAC pseudonyms, no hostnames/IPs/probes), auto-enforced retention (default 90 d), anonymized exports (`privacy.py`, `store.py`, `export.py`, `cli.py`) |
| 4 | Noisy location | Every fix: error radius + `confidence` + `zone_confidence`; **zone is the primary answer**; low-confidence coordinates withheld (`Fix.display`); RSSI-spread demotion (`locate.py`) |
| 5 | Sensitive raw PCAP | `--ack-sensitive` acknowledgement (warns, never blocks), `--strip-payloads` 128-B header-only captures, `--max-age-days` retention, 0600 files (`cli.py`, `backends/sniffer.py`) |
| 6 | Traffic-analysis exposure | Metadata-minimal + **redaction ON by default** (URL queries stripped, UA→product token, hostnames truncated, credential patterns scrubbed, values never logged); `--anonymize-ips` for shared reports (`traffic.py`, `privacy.py`) |
| 7 | IDS false positives | Per-alert `confidence`/`status`/`evidence` + “to confirm” hints, `--sensitivity`, beacon persistence (single sighting = 45, persisted = 78), adaptive noisy-air margin, cross-alert corroboration (`defense.py`) |
| 8 | Ambiguous rogue APs | Noisy-OR scoring over 7 independent indicators; `likely-rogue` needs **≥2 indicators and score ≥ 40**; single-indicator groups listed as `unconfirmed`/`low` and never counted (`engine.py`) |
| 9 | No trust model | `trust.py`: canonical sources with base reliability, ranked binding evidence, noisy-OR fusion (never reaches 100), high/medium/low/very-low labels — surfaced in terminal, CSV and JSON for stations, APs, alerts, rogues and fixes |
| 10 | Sensitive history DB | 0600 at creation + world-readable warnings, `policy` table (salt/retention), `--retain-days` enforced on open, `db` command: `--report`, `--prune-days`, `--delete-mac`, `--anonymize-db --yes` (irreversible), `--purge --yes`, `--vacuum` (`store.py`, `cli.py`) |

Operational notes:

* Pair 0600 file permissions with full-disk encryption for captures/DBs at rest;
  no new dependencies were added, so at-rest encryption stays an OS-layer concern.
* Pseudonym salts live in each database's `policy` table and are **never**
  written to exports; per-export salts make shared reports unlinkable.
* `ephemeral` mode makes persistence calls raise instead of writing — use it for
  live triage on airspace you must not retain data about.
ain data about.
