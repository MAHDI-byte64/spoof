<div align="center">

<h1>🍬 CandyTunnel</h1>

<p><strong>High-performance bidirectional IP-spoofing tunnel for heavily censored networks</strong></p>

<p>
  <a href="https://github.com/AmiRCandy/CandyTunnel/releases/latest"><img src="https://img.shields.io/github/v/release/AmiRCandy/CandyTunnel?style=flat-square&color=ff69b4&label=latest%20release" alt="Latest Release"></a>
  <a href="https://github.com/AmiRCandy/CandyTunnel/actions"><img src="https://img.shields.io/github/actions/workflow/status/AmiRCandy/CandyTunnel/build-release.yml?style=flat-square&label=build" alt="Build Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Linux">
</p>

<p>
  <a href="#-quick-install">Quick Install</a> ·
  <a href="#-how-it-works">How It Works</a> ·
  <a href="#-manager-script">Manager Script</a> ·
  <a href="#-configuration-reference">Configuration</a> ·
  <a href="#-donate">Donate</a>
</p>

</div>

---

> **⚠️ EDUCATIONAL & RESEARCH USE ONLY**
> This software is provided for educational, research, and authorised security-testing purposes only.
> You are solely responsible for compliance with all applicable laws in your jurisdiction.
> Unauthorised use of IP spoofing may be illegal and unethical. The authors assume no liability for misuse.

---

**CandyTunnel** is a Rust-powered tunnel that makes your traffic invisible to censorship systems. Both the client **and** the server forge their source IP addresses, so every packet on the wire looks like it originates from a legitimate, innocent host — a CDN edge node, a public DNS resolver, anything you choose. On top of spoofing, CandyTunnel supports ChaCha20 encryption, packet multiplexing, XOR FEC loss recovery, and a full suite of DPI-evasion tricks, all over your choice of seven transport protocols.

---

## Table of Contents

1. [Features at a Glance](#-features-at-a-glance)
2. [How It Works](#-how-it-works)
3. [Quick Install](#-quick-install)
4. [Manager Script](#-manager-script)
5. [Web Management Panel](#-web-management-panel)
6. [Manual Build](#-manual-build)
7. [Quick Start (manual)](#-quick-start-manual)
8. [Configuration Reference](#-configuration-reference)
9. [Performance Tuning](#-performance-tuning)
10. [Security & Encryption](#-security--encryption)
11. [Operational Notes](#-operational-notes)
12. [Donate](#-donate)
13. [License](#-license)

---

## ✨ Features at a Glance

| Feature | Details |
|---|---|
| 🎭 **Mutual IP spoofing** | Both client and server forge source IPs — blends seamlessly into real traffic |
| 🔄 **Spoofed-IP rotation** | Per-session pool of IPs for stronger traffic-pattern evasion |
| 🚇 **7 transport protocols** | UDP · ICMP · Proto58 · TCP · QUIC · IPIP · GRE — pick what survives your network |
| 📦 **Multiplexing** | Batches multiple packets per wire frame, cutting syscall overhead drastically |
| 🛡️ **XOR FEC** | Forward Error Correction — recovers lost packets without retransmission |
| 🔐 **ChaCha20 encryption** | 3–8 GB/s hardware-accelerated stream cipher, fresh nonce per frame |
| ⚡ **Parallel tunnels** | Configurable independent tunnel streams for maximum throughput |
| 🧠 **Auto-tuning** | Detects CPU cores, RAM, and NIC speed to set optimal runtime parameters |
| 🏎️ **mimalloc allocator** | 2–4× faster than glibc under concurrent multi-threaded workloads |
| 🌐 **TUN + port forwarding** | Kernel-level IP tunnel with TCP/UDP port filters and iptables NAT |
| 🔑 **HMAC-SHA256 auth** | Pre-shared key authentication — unknown peers silently dropped |
| 🎨 **Beautiful logging** | Coloured, structured, aligned output with startup banner |
| 🖥️ **Web management panel** | Embedded bilingual (فارسی/English) admin UI — manage instances, logs, and the IP tester from the browser |

---

## ⚙️ How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│  Your Application  (any TCP / UDP / ICMP traffic)                │
└─────────────────────────┬────────────────────────────────────────┘
                          │  routed to tun_peer_ip : forward_ports
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│  TUN interface  (candy0)                                         │
│  iptables NAT redirects forward_ports → tun_peer_ip             │
└─────────────────────────┬────────────────────────────────────────┘
                          │  CandyPacket [magic|ver|kind|id|seq|payload]
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│  [ Optional ChaCha20 encrypt ]  →  [ Optional Mux / FEC frame ] │
└─────────────────────────┬────────────────────────────────────────┘
                          │
                          ▼
    Raw IPv4  src=spoofed_client_ip   dst=real_server_ip
    ════════════════════  censored network  ════════════════════
    Raw IPv4  src=real_server_ip
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│  Server: demux by tunnel_id → decrypt → deliver to TUN           │
└─────────────────────────┬────────────────────────────────────────┘
                          │
                          ▼
    Raw IPv4  src=spoofed_server_ip   dst=real_client_ip
    ════════════════════  censored network  ════════════════════
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│  Your Application receives response                              │
└──────────────────────────────────────────────────────────────────┘
```

**Transport modes at a glance:**

| Protocol | IP Proto | L4 Header | Mux/FEC | Notes |
|---|---|---|---|---|
| `udp` | 17 | UDP (8 B) | ✅ | Most compatible |
| `icmp` | 1 | ICMP Echo (8 B) | ✅ | Blends with ping traffic |
| `proto58` | 58 | none | ✅ | IPv6-neighbour-discovery camouflage |
| `tcp` | 6 | TCP (20 B) | ❌ | Looks like HTTP/HTTPS; fake-TLS option |
| `quic` | 17+QUIC | UDP+QUIC | ❌ | Full QUIC stream with TLS 1.3 |
| `ipip` | 4 | none | ✅ | RFC 2003 — indistinguishable from a real IPIP tunnel |
| `gre` | 47 | GRE (4 B) | ✅ | RFC 2784 — looks identical to a real GRE VPN to any DPI |

---

## 🚀 Quick Install

The fastest way to get started is the **Manager Script**. It downloads the latest pre-built binary from GitHub Releases and walks you through every config option interactively.

```bash
# Download the manager script
curl -fsSL https://raw.githubusercontent.com/AmiRCandy/CandyTunnel/main/scripts/candy-manager.sh \
  -o candy-manager.sh

# Run the full guided setup (requires root)
sudo bash candy-manager.sh setup
```

The wizard handles everything: binary download, full config file generation (every option is configurable), systemd service creation, and optional immediate start.

---

## 🎛️ Manager Script

`scripts/candy-manager.sh` is a complete lifecycle management tool. The interactive wizard covers **every** available option, organised into 11 sections:

| # | Section | What you configure |
|---|---|---|
| 1 | **Role** | `client` or `server` |
| 2 | **Spoofing mode** | Full IP spoofing or no-spoof mode (real IPs) |
| 3 | **IP Addressing** | Real IPs, spoofed IPs, spoofed-IP pool, extra allowed peers |
| 4 | **Transport** | Protocol pair, data port, port-shuffle range, ICMP ID and randomisation |
| 5 | **Mux & FEC** | Enable/disable, flush interval ms, payload size, FEC group size |
| 6 | **QUIC** | SNI, cert/key paths, ALPN, timeouts, flow-control windows + auto cert-gen |
| 7 | **Security** | Pre-shared key, ChaCha20 toggle, custom `xor_key` |
| 8 | **DPI Obfuscation** | Padding, padding max size, TTL jitter, fake TLS header, random DSCP |
| 9 | **TUN Interface** | Name, local/peer TUN IPs, netmask, MTU, TUN MTU, physical NIC, port forwarding |
| 10 | **Performance** | Mode, auto-tune, tunnel count, channel capacities, worker threads |
| 11 | **Logging** | Log level |

### Spoofing vs No-Spoofing

| Choice | What happens |
|---|---|
| **Yes — enable spoofing** | You supply fake source IPs; both sides forge source on every packet — maximum DPI and censorship evasion |
| **No — disable spoofing** | `spoofed_ip` is set to `real_ip`, `peer_spoofed_ip` to `peer_real_ip` — tunnel operates normally with real addresses, no forgery |

> ⚠️ **Both sides must match.** If the server expects a spoofed source but the client sends its real IP, all packets are silently dropped.

### All commands

```bash
# ── Setup & Installation ─────────────────────────────────────────
sudo bash candy-manager.sh setup            # Full guided setup: download + configure
sudo bash candy-manager.sh download         # (Re-)download latest binary from GitHub
sudo bash candy-manager.sh update           # Update to latest release, restart services
sudo bash candy-manager.sh configure        # Add / reconfigure an instance
sudo bash candy-manager.sh gen-quic-cert    # Generate self-signed TLS cert for QUIC
sudo bash candy-manager.sh uninstall        # Remove all services, binary, install dir

# ── Service Control ──────────────────────────────────────────────
sudo bash candy-manager.sh start   <name>   # Start an instance
sudo bash candy-manager.sh stop    <name>   # Stop a running instance
sudo bash candy-manager.sh restart <name>   # Restart after a config change
sudo bash candy-manager.sh enable  <name>   # Enable auto-start on boot
sudo bash candy-manager.sh disable <name>   # Disable auto-start on boot
sudo bash candy-manager.sh remove  <name>   # Stop, disable, and delete an instance

# ── Monitoring ───────────────────────────────────────────────────
sudo bash candy-manager.sh status           # Dashboard showing all instances
sudo bash candy-manager.sh list             # List configured instance names
sudo bash candy-manager.sh logs  <name> 100 # Show last 100 log lines
sudo bash candy-manager.sh follow <name>    # Live log tail (Ctrl-C to exit)
```

### File layout

```
/opt/candytunnel/candy-tunnel               ← installed binary
/etc/candytunnel/<name>.toml                ← instance config file
/etc/systemd/system/candytunnel@.service    ← systemd template unit
/usr/local/bin/candy-tunnel                 ← convenience symlink
```

**Requirements:** Linux with systemd · `curl` · `ip` · `iptables` · root/sudo

---

## 🖥️ Web Management Panel

CandyTunnel ships an **embedded** web panel — a single self-contained HTTP server
built into the binary (no external web framework, no Node, no extra services).
It serves a **bilingual (فارسی / English), RTL-aware** admin UI with a dark/light
theme for managing everything from the browser:

- 📊 **Dashboard** — host CPU/RAM/uptime/load and a live overview of every instance
- 🚇 **Instances** — create, edit (every config option), start/stop/restart,
  enable/disable on boot, and delete — writes the same `/etc/candytunnel/*.toml`
  files and `candytunnel@<name>.service` units as the manager script
- 🎯 **IP Tester** — launch a spoofed-IP latency sweep and view **ranked**,
  fastest-first results right in the browser
- 📜 **Logs** — live `journalctl` tail per instance

### Setup

The easiest path is the manager script:

```bash
sudo bash candy-manager.sh panel        # writes panel config, sets password, starts service
```

Or manually with the unified binary:

```bash
# 1. Set the login password (stored only as a salted SHA-256 hash)
sudo candy-tunnel panel --config /etc/candytunnel/panel.toml --set-password

# 2. Run it (foreground, or via the candytunnel-panel.service unit)
sudo candy-tunnel panel --config /etc/candytunnel/panel.toml
```

Then open **`http://127.0.0.1:8088`**.

### Panel commands (manager script)

```bash
sudo bash candy-manager.sh panel          # first-time setup (config + password + service)
sudo bash candy-manager.sh panel-passwd   # change the login password
sudo bash candy-manager.sh panel-start    # start the panel service
sudo bash candy-manager.sh panel-stop     # stop the panel service
sudo bash candy-manager.sh panel-restart  # restart
sudo bash candy-manager.sh panel-logs 100 # last 100 panel log lines
```

### Security

> ⚠️ The panel runs as **root** (it drives `systemctl` and raw-socket IP tests).
> Treat access to it as full control of the host.

- Binds **`127.0.0.1` by default** — reach it over SSH:
  `ssh -L 8088:127.0.0.1:8088 user@server`, then browse to `localhost:8088`.
  A non-loopback bind is allowed but logged as a warning — put it behind TLS/a firewall.
- **Password login** required; sessions are 256-bit opaque tokens in an
  `HttpOnly; SameSite=Strict` cookie. The password is stored only as a salted
  SHA-256 hash.
- Mutating requests require an `X-CandyTunnel` header (set by the UI) which,
  with `SameSite=Strict`, defeats CSRF. Login attempts are rate-limited per source IP.
- Instance names are strictly validated and **no user input ever reaches a shell**
  (commands run via `argv`, never `sh -c`).

| Panel config key | Default | Description |
|---|---|---|
| `bind` | `127.0.0.1:8088` | Listen address `host:port` |
| `session_ttl_secs` | `3600` | Session lifetime (sliding) |
| `config_dir` | `/etc/candytunnel` | Where instance `*.toml` files live |
| `bin_path` | `/opt/candytunnel/candy-tunnel` | Binary the panel drives |
| `service_prefix` | `candytunnel` | systemd unit prefix (`<prefix>@<name>.service`) |

---

## 🔧 Manual Build

### Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Linux (raw socket support required) |
| **Privileges** | `CAP_NET_RAW` + `CAP_NET_ADMIN`, or root |
| **Rust** | 1.75+ (edition 2021) |
| **Build tools** | `cargo`, `gcc` / `clang` |

### Build commands

```bash
# Standard release build
cargo build --release

# Maximum performance — enables AVX2/AVX-512/NEON for ChaCha20, FEC, and checksums
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Output binaries

```
target/release/candy-tunnel   ← unified binary (client + server via role = "...")
target/release/client         ← client-only binary
target/release/server         ← server-only binary
```

---

## ▶️ Quick Start (manual)

### 1. Start the server

```bash
sudo ./target/release/candy-tunnel --config config/server.toml
```

For QUIC, generate a TLS certificate first:

```bash
openssl req -x509 -newkey rsa:2048 -keyout config/quic_key.pem \
    -out config/quic_cert.pem -days 365 -nodes -subj "/CN=CandyTunnel"
```

### 2. Start the client

```bash
sudo ./target/release/candy-tunnel --config config/client.toml
```

The client creates a TUN interface (`tun_name`, default `candy0`) and installs iptables NAT rules for `forward_ports`. Traffic routed to `tun_peer_ip` on those ports is forwarded through the tunnel.

### Log level

Control verbosity with `--log-level` or the `log_level` config key:

| Level | Use |
| `error` | Failures only |
| `warn` | Warnings + errors |
| `info` | **Default** — startup, tunnel events, stats |
| `debug` | Detailed per-packet flow |
| `trace` | Full wire-level dump (very verbose) |

### Spoofed IP check mode (IP tester)

Measures latency for a list of candidate spoofed source IPs to find which ones
survive your path. Each candidate is probed several times concurrently and the
**fastest** reply is kept, so a single dropped packet no longer mislabels a good
IP. Results are written **ranked fastest-first**, with a reachable/timeout
summary — and the same sweep is available in the [web panel](#-web-management-panel).

```bash
# Server — allow any source for the sweep:
sudo ./target/release/candy-tunnel --config config/server.toml --check-allow-any

# Client — sweep the candidate list:
sudo ./target/release/candy-tunnel --config config/client.toml \
    --check --check-ips spoof_list.txt --check-out latency.txt \
    --check-probes 2 --check-timeout-ms 1500 --check-workers 64
```

| Flag | Default | Description |
|---|---|---|
| `--check-ips` | — | Candidate list file (one IPv4 per line; `#` comments and duplicates ignored) |
| `--check-out` | `check_latency.txt` | Ranked output file |
| `--check-probes` | `2` | SYN probes per IP (fastest reply wins) |
| `--check-timeout-ms` | `1500` | Per-IP timeout |
| `--check-workers` | `64` | Concurrent candidates |

`latency.txt` output (ranked, fastest first; latency in ms):
```
# CandyTunnel spoofed-IP check results (ranked fastest-first)
# total=3 reachable=2 timeouts=1
# columns: ip  latency_ms|timeout
1.1.1.1         18
8.8.4.4         23
5.6.7.8         timeout
```

---

## 📋 Configuration Reference

Both `config/client.toml` and `config/server.toml` share the same schema.  
The manager script generates a fully-commented config file covering every option.

### IP Addressing

| Field | Side | Default | Description |
|---|---|---|---|
| `role` | both | — | `"client"` or `"server"` |
| `real_ip` | both | — | Physical IPv4 address of this node |
| `peer_real_ip` | both | — | Physical IPv4 address of the remote node |
| `spoofed_ip` | both | — | Fake source IP placed in every outgoing packet |
| `peer_spoofed_ip` | both | — | Fake source IP expected from the peer |
| `spoofed_ip_pool` | both | `[]` | Pool of IPs rotated each session for stronger evasion |
| `allowed_peers` | both | `[]` | Extra trusted peer IPs beyond `peer_real_ip` |

### Transport

| Field | Side | Default | Description |
|---|---|---|---|
| `uplink_protocol` | both | `"udp"` | Outbound transport: `udp` · `icmp` · `proto58` · `tcp` · `quic` · `ipip` · `gre` |
| `downlink_protocol` | both | `"udp"` | Inbound transport |
| `data_port` | both | — | UDP/TCP destination port (must match both sides) |
| `shuffle_data_port` | both | `false` | Randomise data port per packet (UDP/TCP only) |
| `shuffle_port_min` | both | `49152` | Lower bound of the shuffle port range |
| `shuffle_port_max` | both | `65535` | Upper bound of the shuffle port range |
| `icmp_id` | both | `0x4321` | ICMP echo identifier (must match both sides) |
| `random_icmp_id` | both | `false` | Randomise ICMP echo identifier per packet |

### Multiplexing & FEC

> Applies to UDP / ICMP / Proto58 / IPIP — **not** TCP or QUIC.

| Field | Side | Default | Description |
|---|---|---|---|
| `enable_multiplex` | both | `true` | Batch multiple packets per wire frame |
| `multiplex_flush_ms` | both | `1` | Max wait before flushing a partial batch (ms) |
| `multiplex_max_payload` | both | `1380` | Max wire-frame payload size (bytes) |
| `enable_fec` | both | `false` | XOR Forward Error Correction |
| `fec_group_size` | both | `4` | Data frames per parity frame (≥ 2) |

### QUIC

> Only used when `uplink_protocol` or `downlink_protocol` is `"quic"`.

| Field | Side | Default | Description |
|---|---|---|---|
| `quic_server_name` | both | `"CandyTunnel"` | TLS SNI used by the client |
| `quic_cert` | server | `"config/quic_cert.pem"` | TLS certificate path |
| `quic_key` | server | `"config/quic_key.pem"` | TLS private key path |
| `quic_alpn` | both | `"h3"` | ALPN label |
| `quic_idle_timeout_ms` | both | `30000` | Idle connection timeout (ms) |
| `quic_max_data` | both | `134217728` | Connection-level flow-control window (128 MB) |
| `quic_max_stream_data` | both | `16777216` | Per-stream flow-control window (16 MB) |
| `quic_max_streams_bidi` | both | `256` | Max concurrent bidirectional streams |

### Security

| Field | Side | Default | Description |
|---|---|---|---|
| `pre_shared_key` | both | — | HMAC-SHA256 packet authentication key |
| `enable_xor` | both | `false` | Enable ChaCha20 stream-cipher on all wire frames |
| `xor_key` | both | *(empty)* | Encryption key — derived from `pre_shared_key` when empty |

> ⚠️ Both sides must have **identical** `enable_xor` and `xor_key`. A mismatch causes all packets to silently fail decoding.

### DPI Bypass Obfuscation

> All settings are independent. **Both sides must be identical.**

| Field | Side | Default | Description |
|---|---|---|---|
| `packet_padding` | both | `false` | Append 1–`packet_padding_max` random bytes after every frame — breaks length fingerprinting |
| `packet_padding_max` | both | `64` | Upper bound on random padding (1–255 bytes) |
| `ttl_jitter` | both | `false` | Randomise IPv4 TTL from `{64, 128, 255}` — fixed TTL=64 is a raw-socket fingerprint |
| `fake_tls_header` | both | `false` | Prefix every TCP payload with a 5-byte fake TLS Application Data record — shallow DPI sees TLS |
| `random_dscp` | both | `false` | Set a random plausible DSCP value `{0x00, 0x28, 0x10}` in the IPv4 ToS field |

### TUN Interface

| Field | Side | Default | Description |
|---|---|---|---|
| `tun_name` | both | `"candy0"` | TUN interface name |
| `tun_ip` | both | — | Local TUN IPv4 address |
| `tun_peer_ip` | both | — | Peer TUN IPv4 address (**swap** between client and server) |
| `tun_netmask` | both | `255.255.255.252` | TUN netmask (`/30` point-to-point) |
| `tun_mtu` | both | *(equals `mtu`)* | TUN MTU (clamped to `mtu`) |
| `interface` | both | `"eth0"` | Physical NIC name for raw socket binding |
| `forward_ports` | client | `[]` | TCP/UDP ports to forward through the tunnel (empty = all) |

### Performance

| Field | Side | Default | Description |
|---|---|---|---|
| `perf_mode` | both | `"throughput"` | `throughput` · `latency` · `balanced` |
| `auto_tune` | both | `true` | Auto-detect CPU/RAM/NIC and set optimal parameters |
| `tunnel_count` | both | `4` | Parallel tunnel streams (overridden by `auto_tune`) |
| `mtu` | both | `1380` | Max payload bytes per packet |
| `channel_capacity` | both | `8192` | Per-tunnel async channel capacity |
| `io_channel_capacity` | both | `16384` | Raw I/O and mux queue capacity |
| `runtime_worker_threads` | both | `0` | Tokio worker threads (0 = auto) |

### Logging

| Field | Side | Default | Description |
|---|---|---|---|
| `log_level` | both | `"info"` | `trace` · `debug` · `info` · `warn` · `error` |

---

## 📈 Performance Tuning

### Auto-tune (on by default)

With `auto_tune = true` the runtime inspects your hardware and sets:

| Parameter | Throughput mode | Latency mode |
|---|---|---|
| Worker threads | All cores | ≤ 4 cores |
| Tunnel count | `cores × 2` + NIC boost (cap 64) | `cores / 2` |
| Channel capacity | `8192 × RAM multiplier` | `2048 × RAM multiplier` |
| I/O channel | `2 × channel_capacity` | `2 × channel_capacity` |
| Mux enabled | yes — 1 ms flush | no |

NIC speed tiers add extra tunnels: **+1** at 1 Gbps · **+2** at 2 Gbps · **+3** at 5 Gbps · **+4** at 10 Gbps.

### Manual tips

- `perf_mode = "throughput"` — maximises raw bandwidth (bulk transfer)
- `perf_mode = "latency"` — minimises RTT (gaming, VoIP) — disables mux
- `perf_mode = "balanced"` — safe all-round default
- **Tune `mtu`** to your actual path MTU (`tracepath <peer>` helps); 1380 is safe for most paths
- **`spoofed_ip_pool`** with 3–5 addresses distributes traffic and resists rate-limiting
- **Build with `target-cpu=native`** to unlock AVX2/NEON SIMD for ChaCha20 and FEC

### Internal optimisations

| Feature | Impact |
|---|---|
| **mimalloc** | 2–4× faster than glibc under concurrent multi-threaded load |
| **ArcSwap tunnel pool** | Lock-free read path — one atomic pointer load per forwarded packet |
| **Dedicated TUN I/O threads** | Separate reader/writer threads per TUN; no `spawn_blocking` per packet |
| **4 MB socket buffers** | `SO_SNDBUF`/`SO_RCVBUF` set to 4 MiB — absorbs 1 Gbps+ bursts |
| **Atomic IP ID counter** | Replaces `rand::random()` per packet with a wrapping `AtomicU16` (~10× faster) |
| **ChaCha20 stream cipher** | 3–8 GB/s vs ~700 MB/s for the previous SHA-256 CTR design |
| **SYN handshake retransmission** | The client re-sends its SYN every 500 ms until the SYN-ACK arrives (≈15 s budget), so one dropped handshake packet on a lossy/filtered path no longer fails startup |
| **Overhead-aware TUN MTU** | The effective TUN MTU is auto-clamped for the XOR nonce, DPI padding, and mux/encapsulation headers so a full-size packet rides in a single un-fragmented wire frame |
| **DF bit cleared** | Avoids silent black-holes when path MTU < configured MTU |
| **Raised QUIC windows** | 128 MB connection / 16 MB stream — prevents flow-control throttling on fast links |
| **Raised default capacities** | `channel_capacity` 8192, `io_channel_capacity` 16384 (was 4096 each) |

---

## 🔒 Security & Encryption

### Pre-shared key authentication

Set `pre_shared_key` to the **same value** on both sides. Packets from unknown peers are silently dropped.

### ChaCha20 wire encryption

Enable on **both** sides:

```toml
enable_xor = true
# xor_key = ""   # leave empty to derive key automatically from pre_shared_key
```

Wire format when enabled:

```
[ nonce : 12 bytes ][ ChaCha20-encrypted payload : N bytes ]
```

- Fresh random 12-byte nonce per frame — identical payloads always produce different ciphertext
- Key derived from `xor_key` (or `pre_shared_key`) via SHA-256
- **Confidentiality + DPI evasion**; HMAC auth still protects integrity
- Negligible overhead even at 10 Gbps line rate

### Minimal privileges

```bash
# Grant only the required Linux capabilities — no need for full root:
sudo setcap cap_net_raw,cap_net_admin+ep ./target/release/candy-tunnel
```

### Choosing spoofed IPs

- Use IPs you are **authorised** to emulate (CDN edge nodes, public DNS resolvers)
- Use a `spoofed_ip_pool` of 3–5 addresses to vary traffic patterns
- Note that BCP 38 ingress filtering may drop spoofed sources at some ISPs

---

## 📝 Operational Notes

| Rule | Details |
|---|---|
| **Protocol agreement** | Both sides must use the same `uplink_protocol`, `downlink_protocol`, `data_port`, `icmp_id`, `pre_shared_key`, `enable_xor`, `xor_key` |
| **TUN IPs** | `tun_ip` and `tun_peer_ip` must be **swapped** between client and server |
| **QUIC** | Requires **both** `uplink_protocol = "quic"` and `downlink_protocol = "quic"` |
| **Mux/FEC** | Only for UDP / ICMP / Proto58 / IPIP — unavailable for TCP or QUIC |
| **IPv4 only** | The tunnel forwards IPv4 traffic only; IPv6 is dropped at the TUN |
| **Port shuffle + QUIC** | These two options cannot be used together |
| **Port forwarding** | `forward_ports = []` (empty) forwards **all** TCP/UDP ports arriving at the TUN |
| **Obfuscation** | `packet_padding`, `ttl_jitter`, `fake_tls_header`, `random_dscp` must be identical on both sides |

---

## 💖 Donate

CandyTunnel is free and open-source. If it helps you or your users bypass censorship and stay connected, please consider supporting continued development.

<div align="center">

### 🪙 Cryptocurrency Donations

| Network | Currency | Address |
|:---:|:---:|:---|
| ![TRON](https://img.shields.io/badge/TRON-TRC20-red?style=flat-square) | TRX / USDT (TRC20) | `TVRmCLBw8p3ZpNnuZBGgk5sZA5izMQ18AK` |
| ![ETH](https://img.shields.io/badge/Ethereum-ERC20-blue?style=flat-square) | USDT (ERC20) | `0x622ed192856de590a3cd132fb45f9595a2656527` |
| ![TON](https://img.shields.io/badge/TON-Network-0088cc?style=flat-square) | TON | `UQB79j_1LB_I3TRgBibzyO3O5KcDiq0lviDke3XoiyOVJxV4` |

*Every contribution — no matter how small — helps keep this project alive and actively maintained. Thank you! 🙏*

</div>

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>Made with ❤️ by <a href="https://github.com/AmiRCandy">AmiRCandy</a> · Built with the assistance of AI 🤖</sub>
</div>
