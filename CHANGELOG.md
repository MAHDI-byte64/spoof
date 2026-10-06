# Changelog

## v4.3.0

### Added
- **Per-packet spoofed-IP rotation** (`spoof_rotation`, on by default): each
  outgoing packet takes the next address from `spoofed_ip_pool` round-robin, so
  a per-IP rate/volume limit on the path hits each address only a fraction as
  hard. `peer_spoofed_ip_pool` lists the addresses the peer rotates through, and
  `spoofed_ip_file` / `peer_spoofed_ip_file` load pools from a file (single IPs,
  CIDR blocks, and `a-b` ranges).
- **Spoofed-IP tester** (`candy-tunnel tester {sender|receiver}`, and a panel
  tab): one server forges probes from every candidate address, the other counts
  what arrives per source and reports loss against a threshold. TCP SYN, UDP and
  ICMP probes; candidate lists accept single IPs, CIDR and `a-b` ranges.
- **One-step panel setup**: a **connection code** exported from the server
  tunnel that the client imports to fill in every shared setting automatically;
  a simple quick-add form with real-IP / interface auto-detect; and a per-tunnel
  spoofed-IP list editor. One-line installer at `scripts/install.sh`.
- **Panel redesign**: Persian/RTL by default with an English (LTR) toggle, dark
  and light themes, and an accent picker.

### Changed / Fixed
- **Peer allow-check honours the pool** — `is_peer_allowed` now accepts every
  `peer_spoofed_ip_pool` member, so a peer rotating its source IP is not dropped
  by the app-level guard (previously only the primary peer IP passed, which
  silently dropped all rotated DATA packets).
- **Handshake wakeup** — `wait_established` registers its event listener before
  checking tunnel state, closing a lost-wakeup window that could delay a
  handshake by a full retransmit slice.
- `send_threads` now defaults to **1** so packets leave in order (several send
  threads draining one queue let packets overtake each other, which TCP inside
  the tunnel reads as loss).

## v4.2.0

### Added
- **Embedded web management panel** (`candy-tunnel panel`): a self-contained
  HTTP server with a bilingual (فارسی/English), RTL-aware, dark/light admin UI.
  Manage instances (create/edit/start/stop/restart/enable/disable/delete), tail
  logs, and view host stats from the browser.
  - Password login (salted SHA-256), 256-bit `HttpOnly; SameSite=Strict`
    session cookies, per-IP login throttling, CSRF header guard, strict
    instance-name validation, and no shell interpolation (argv only).
  - Strict `Content-Security-Policy`, `X-Frame-Options: DENY`,
    `Referrer-Policy: no-referrer` on every response.
  - `candy-manager.sh` gains `panel`, `panel-passwd`, `panel-start/stop/restart`,
    `panel-logs`.
- **In-panel iperf3 speed test** — measure real end-to-end tunnel throughput
  (upload/download, TCP/UDP) from the dashboard.
- **Throughput scaling** for the raw-socket I/O:
  - Multi-threaded sharded send — `send_threads` parallel senders, each with its
    own raw socket, so packet building/sending scales across CPU cores.
  - `sendmmsg` / `recvmmsg` batching (`send_batch` / `recv_batch`) to amortize
    per-packet syscalls on both directions.

### Changed / Fixed
- **SYN handshake retransmission** — the client re-sends its SYN until the
  SYN-ACK arrives (~15 s budget), surviving a dropped handshake packet on
  lossy/filtered paths.
- **Overhead-aware TUN MTU** — the effective TUN MTU is clamped for the XOR
  nonce, DPI padding, and mux/encapsulation headers so a full-size packet rides
  in a single un-fragmented wire frame; the mux-frame cap is kept within the MTU
  budget.
- **Optimized spoofed-IP tester** — multiple concurrent probes per IP (fastest
  reply wins), de-duplicated input, ranked fastest-first output with a
  reachable/timeout summary, and live progress. New `--check-probes` flag.
- Centralized cross-field config validation (`Config::from_toml_str` /
  `validate`): rejects one-sided QUIC, identical TUN IPs, tiny MTU, etc.
- Removed dead code, fixed the broken `logging` doctest, and cleared all
  compiler warnings.

### Notes
- GSO (`UDP_SEGMENT`) is intentionally not used: it is incompatible with the
  `IP_HDRINCL` raw sockets required for source-IP spoofing and with the tunnel's
  variable-length mux frames. `sendmmsg`/`recvmmsg` is the correct equivalent.
