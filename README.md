# 🔍 DPI Engine — Deep Packet Inspection System

> A pure-Java Deep Packet Inspection tool that reads PCAP network captures, identifies applications from encrypted TLS traffic, applies blocking rules, and writes filtered output — with both single-threaded and high-performance multi-threaded modes.

---

## Table of Contents

- [What is DPI?](#what-is-dpi)
- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
  - [SNI Extraction](#sni-extraction)
  - [Application Classification](#application-classification)
  - [Flow-Level Blocking](#flow-level-blocking)
- [Architecture](#architecture)
  - [Single-Threaded Mode](#single-threaded-mode)
  - [Multi-Threaded Mode](#multi-threaded-mode)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build from Source](#build-from-source)
  - [Generate Test Traffic](#generate-test-traffic)
  - [Run the Engine](#run-the-engine)
- [CLI Reference](#cli-reference)
- [Sample Output](#sample-output)
- [Extending the Project](#extending-the-project)
- [Troubleshooting](#troubleshooting)

---

## What is DPI?

**Deep Packet Inspection (DPI)** examines the *contents* of network packets beyond just headers. Unlike a simple firewall that only looks at IP addresses and ports, DPI looks inside the payload to identify what application or website is generating the traffic.

**Real-world uses:**
- ISPs throttling or blocking certain applications (e.g. BitTorrent)
- Enterprises blocking social media on office networks
- Parental controls blocking inappropriate websites
- Security systems detecting malware

```
User Traffic (PCAP) ──► [DPI Engine] ──► Filtered Traffic (PCAP)
                               │
                         - Identifies apps (YouTube, Netflix, etc.)
                         - Blocks based on rules
                         - Generates reports
```

---

## Features

- ✅ **PCAP read/write** — compatible with Wireshark captures
- ✅ **Full protocol parsing** — Ethernet → IPv4 → TCP / UDP
- ✅ **TLS SNI extraction** — identifies HTTPS destinations without decryption
- ✅ **HTTP Host extraction** — identifies plain HTTP destinations
- ✅ **20 application types** — YouTube, Netflix, GitHub, Discord, TikTok, and more
- ✅ **Flexible blocking rules** — by source IP, application type, or domain pattern
- ✅ **Flow-level state tracking** — blocks entire connections, not just individual packets
- ✅ **Two engine modes** — simple single-threaded and high-throughput multi-threaded
- ✅ **Zero dependencies** — pure Java standard library, no external JARs needed

---

## Project Structure

```
src/main/java/com/dpi/
├── Main.java                          ← CLI entry point & argument parsing
│
├── model/
│   ├── AppType.java                   ← Application enum + SNI → App mapping
│   ├── FiveTuple.java                 ← Connection identifier (src/dst IP, ports, protocol)
│   ├── Flow.java                      ← Per-connection state (SNI, app, blocked flag)
│   ├── RawPacket.java                 ← Raw bytes + timestamp from PCAP
│   └── ParsedPacket.java              ← Parsed protocol fields
│
├── pcap/
│   ├── PcapReader.java                ← Reads PCAP files (handles endianness)
│   └── PcapWriter.java                ← Writes filtered PCAP output
│
├── parser/
│   └── PacketParser.java              ← Ethernet / IPv4 / TCP / UDP header parsing
│
├── sni/
│   ├── SNIExtractor.java              ← Extracts hostname from TLS Client Hello
│   └── HTTPHostExtractor.java         ← Extracts Host header from HTTP requests
│
├── rules/
│   └── RuleManager.java               ← IP, app-type, and domain blocking rules
│
├── engine/
│   ├── DpiEngine.java                 ← Single-threaded pipeline
│   ├── MultiThreadedDpiEngine.java    ← Multi-threaded orchestrator
│   ├── LoadBalancer.java              ← LB thread: routes packets to Fast Paths
│   ├── FastPath.java                  ← FP thread: DPI inspection + forward/drop
│   ├── ConnectionTracker.java         ← Per-thread flow table (HashMap, no locks)
│   └── Stats.java                     ← Thread-safe counters (AtomicLong)
│
└── util/
    └── ThreadSafeQueue.java           ← Bounded blocking queue (ReentrantLock + Condition)
```

---

## How It Works

### SNI Extraction

Even though HTTPS traffic is encrypted, the **TLS Client Hello** packet — sent before any encryption is established — contains the destination hostname in plaintext. This is the **Server Name Indication (SNI)** extension, and it's the core technique behind DPI for HTTPS.

```
Browser visits https://www.youtube.com

  Client ──── TLS Client Hello ────► Server
              │
              └─ Extension: SNI
                 └─ hostname: "www.youtube.com"  ← visible in plaintext!

  Client ◄─── Server Hello ─────── Server
              (from here on, everything is encrypted)
```

`SNIExtractor.java` parses the raw TLS record byte-by-byte:

```
TLS Record:
  Byte 0:      0x16  (Handshake content type)
  Bytes 1-2:   0x0301 (TLS version)
  Bytes 3-4:   Record length

Handshake:
  Byte 5:      0x01  (Client Hello type)
  Bytes 6-8:   Length (24-bit)

Client Hello body:
  [skip] Client Version (2) + Random (32) + Session ID + Cipher Suites + Compression
  Extensions:
    Type 0x0000 = SNI Extension
      └─ hostname = "www.youtube.com"  ✓ EXTRACTED
```

### Application Classification

Once the SNI is extracted, `AppType.fromSni()` maps it to a known application using substring matching:

| SNI contains | → AppType |
|---|---|
| `youtube` | `YOUTUBE` |
| `facebook` | `FACEBOOK` |
| `instagram` | `INSTAGRAM` |
| `netflix` | `NETFLIX` |
| `github` | `GITHUB` |
| `discord` | `DISCORD` |
| `tiktok` | `TIKTOK` |
| `spotify` | `SPOTIFY` |
| `zoom` | `ZOOM` |
| `telegram` | `TELEGRAM` |
| `microsoft` | `MICROSOFT` |
| `google` | `GOOGLE` |
| *(port 80)* | `HTTP` |
| *(port 53/UDP)* | `DNS` |

### Flow-Level Blocking

Blocking operates at the **flow level**, not the packet level. The engine tracks every connection by its five-tuple `(srcIP, dstIP, srcPort, dstPort, protocol)`. Once a flow is identified as blocked, all subsequent packets in that connection are dropped:

```
Connection to YouTube (flow: 192.168.1.100:54321 → 142.250.185.206:443)

  Packet 1: TCP SYN          → no SNI yet    → FORWARD
  Packet 2: TCP SYN-ACK      → no SNI yet    → FORWARD
  Packet 3: TCP ACK           → no SNI yet    → FORWARD
  Packet 4: TLS Client Hello  → SNI: www.youtube.com
                              → App: YOUTUBE  (blocked!)
                              → Flow marked BLOCKED → DROP
  Packet 5+: TLS Data         → Flow is BLOCKED    → DROP
```

---

## Architecture

### Single-Threaded Mode

`DpiEngine.java` — sequential processing, ideal for learning or small captures:

```
PcapReader
    │  readNextPacket()
    ▼
RawPacket
    │  PacketParser.parse()
    ▼
ParsedPacket  ──────────────────────────────────────────────┐
    │  ConnectionTracker.getOrCreate(5-tuple)               │
    ▼                                                        │
  Flow                                                       │
    │  SNIExtractor / HTTPHostExtractor                      │
    ▼                                                        │
  SNI  →  AppType.fromSni()  →  Flow.appType               │
    │  RuleManager.isBlocked()                               │
    ├── BLOCKED  →  drop (not written)                       │
    └── ALLOWED  →  PcapWriter.writePacket()  ◄─────────────┘
```

### Multi-Threaded Mode

`MultiThreadedDpiEngine.java` — pipeline of thread pools for high throughput:

```
Reader Thread
  │  hash(5-tuple) % numLbs
  ├──► LB-0 input queue
  └──► LB-1 input queue
              │
        LoadBalancer Thread
          │  hash(5-tuple) % numFps
          ├──► FP-0 input queue
          └──► FP-1 input queue
                      │
                FastPath Thread
                ├── Own ConnectionTracker  (no locks — same flow always routes here)
                ├── SNI / HTTP extraction
                ├── RuleManager check
                └──► Output queue
                          │
                    Writer Thread
                          │
                      output.pcap
```

**Why consistent hashing?**
The same 5-tuple always hashes to the same FastPath thread. This means each FP thread owns its flow table exclusively — **zero locks on the hot path**.

**ThreadSafeQueue** connects every stage. It is a bounded blocking queue backed by `ReentrantLock` + two `Condition` variables (`notEmpty` / `notFull`). When the reader finishes, it closes the LB queues; LBs drain and close the FP queues; FPs drain and close the output queue — clean shutdown with no busy-waiting.

---

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Java JDK | **17 or later** | OpenJDK or Oracle JDK |
| Python 3 | 3.7+ *(optional)* | Only needed to generate test PCAP |

> **No external libraries required.** The entire project uses only the Java standard library.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-username/dpi-engine.git
cd dpi-engine

# Compile
mkdir -p out
javac --release 17 -d out $(find src -name "*.java")

# Build a runnable JAR
echo "Main-Class: com.dpi.Main" > manifest.txt
jar cfm dpi_engine.jar manifest.txt -C out .
```

**Windows (PowerShell):**
```powershell
mkdir out
Get-ChildItem -Recurse -Filter *.java | ForEach-Object { $_.FullName } | Set-Content sources.txt
javac --release 17 -d out @sources.txt
echo "Main-Class: com.dpi.Main" > manifest.txt
jar cfm dpi_engine.jar manifest.txt -C out .
```

### Generate Test Traffic

A Python script is included to create a test PCAP with realistic traffic patterns:

```bash
python3 generate_test_pcap.py
```

This generates `test_dpi.pcap` containing:
- 16 TLS connections with SNI (Google, YouTube, Facebook, Instagram, Twitter, Amazon, Netflix, GitHub, Discord, Zoom, Telegram, TikTok, Spotify, Cloudflare, Microsoft, Apple)
- 2 plain HTTP connections (example.com, httpbin.org)
- 4 DNS queries
- 5 packets from a "blocked" source IP `192.168.1.50`

You can also capture real traffic using **Wireshark**:
1. Open Wireshark → select your network interface → start capture
2. Browse some websites for 30 seconds → stop capture
3. **File → Save As** → Format: `Wireshark/tcpdump — pcap` → save as `capture.pcap`

### Run the Engine

```bash
# Basic run (forward everything)
java -jar dpi_engine.jar test_dpi.pcap output.pcap

# Block YouTube
java -jar dpi_engine.jar test_dpi.pcap output.pcap --block-app YOUTUBE

# Block multiple apps and a source IP
java -jar dpi_engine.jar test_dpi.pcap output.pcap \
    --block-app YOUTUBE \
    --block-app TIKTOK \
    --block-ip 192.168.1.50

# Block by domain pattern
java -jar dpi_engine.jar test_dpi.pcap output.pcap --block-domain facebook

# High-throughput: 4 LB threads × 4 FP threads
java -jar dpi_engine.jar test_dpi.pcap output.pcap --lbs 4 --fps 4

# Force single-threaded mode
java -jar dpi_engine.jar test_dpi.pcap output.pcap --single
```

---

## CLI Reference

```
Usage: java -jar dpi_engine.jar <input.pcap> <output.pcap> [options]
```

| Option | Argument | Description |
|---|---|---|
| `--block-app` | `<APP>` | Block all traffic identified as this application |
| `--block-ip` | `<x.x.x.x>` | Block all packets from a source IP address |
| `--block-domain` | `<pattern>` | Block any flow whose SNI/Host contains this substring |
| `--lbs` | `<N>` | Number of Load Balancer threads (default: `2`) |
| `--fps` | `<N>` | Number of Fast Path threads per LB (default: `2`) |
| `--single` | — | Run in single-threaded mode |

**Valid `--block-app` values:**

```
UNKNOWN  HTTP  HTTPS  DNS  GOOGLE  YOUTUBE  FACEBOOK  INSTAGRAM  TWITTER
AMAZON   NETFLIX  GITHUB  DISCORD  ZOOM  TELEGRAM  TIKTOK  SPOTIFY
CLOUDFLARE  MICROSOFT  APPLE
```

---

## Sample Output

```
[Rules] Blocked app: YOUTUBE
[Rules] Blocked IP: 192.168.1.50

[Mode] Multi-threaded (LBs=2, FPs/LB=2)
╔══════════════════════════════════════════════════════════════╗
║               DPI ENGINE v2.0 (Multi-threaded)               ║
╠══════════════════════════════════════════════════════════════╣
║  Load Balancers:  2    FPs per LB:  2    Total FPs:   4      ║
╚══════════════════════════════════════════════════════════════╝

[Reader] Processing packets from: test_dpi.pcap
[Reader] Done reading 77 packets
[LB0] dispatched=39
[LB1] dispatched=38
[FP0] processed=39 forwarded=34 dropped=5
[FP3] processed=38 forwarded=37 dropped=1

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                                           77  ║
║ Total Bytes:                                           5738  ║
║ TCP Packets:                                             73  ║
║ UDP Packets:                                              4  ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                                               71  ║
║ Dropped:                                                  6  ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║  HTTPS             37  48.1%  #########                      ║
║  UNKNOWN           16  20.8%  ####                           ║
║  HTTP               4   5.2%  #                              ║
║  DNS                4   5.2%  #                              ║
║  YOUTUBE            1   1.3%              (BLOCKED)          ║
║  FACEBOOK           1   1.3%                                 ║
║  GITHUB             1   1.3%                                 ║
╠══════════════════════════════════════════════════════════════╣
║                  DETECTED DOMAINS / SNIs                     ║
╠══════════════════════════════════════════════════════════════╣
║  - www.youtube.com  -> YOUTUBE                               ║
║  - www.facebook.com -> FACEBOOK                              ║
║  - github.com       -> GITHUB                                ║
║  - discord.com      -> DISCORD                               ║
║  - zoom.us          -> ZOOM                                  ║
╚══════════════════════════════════════════════════════════════╝

[Done] Output written to: output.pcap
```

---

## Extending the Project

### Add a New Application

```java
// 1. Add to AppType.java enum:
TWITCH,
REDDIT,

// 2. Add to AppType.fromSni():
if (lower.contains("twitch")) return TWITCH;
if (lower.contains("reddit")) return REDDIT;
```

### Add a New Rule Type (e.g. Block by Destination Port)

```java
// In RuleManager.java:
private final Set<Integer> blockedPorts = new HashSet<>();

public void blockPort(int port) {
    blockedPorts.add(port);
}

// In isBlocked() — add:
if (blockedPorts.contains(dstPort)) return true;
```

### Capture Live Traffic (with Pcap4J)

```java
// Add Pcap4J dependency, then replace PcapReader with:
PcapHandle handle = Pcaps.openLive("eth0", 65535,
    PromiscuousMode.PROMISCUOUS, 10, TimestampPrecision.NANO);

handle.loop(-1, packet -> {
    RawPacket raw = new RawPacket(..., packet.getRawData());
    // push to engine
});
```

---

## Troubleshooting

**`Not a valid PCAP file (bad magic)` error**
> The file may be PCAPNG format. In Wireshark: File → Save As → format: `Wireshark/tcpdump — pcap`.

**All traffic shows `UNKNOWN` or `HTTPS` — no app names**
> SNI is only in the TLS Client Hello (first data packet). Your capture must start from the beginning of the TCP connection. Try capturing from before you open the browser tab.

**Some HTTPS connections never get classified**
> Some servers use ECH (Encrypted Client Hello), a newer TLS feature that encrypts the SNI field. These connections correctly fall back to `HTTPS`.

**Multi-threaded mode uses only 2 of the 4 FP threads**
> This is normal — consistent hashing distributes flows unevenly if there are few distinct 5-tuples. With large real-world captures, all threads will be active.

**`OutOfMemoryError` on very large PCAPs**
> Reduce queue buffer sizes in `MultiThreadedDpiEngine.java`:
> ```java
> private static final int LB_QUEUE_CAPACITY  = 1024;  // was 4096
> private static final int OUT_QUEUE_CAPACITY = 2048;  // was 8192
> ```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
