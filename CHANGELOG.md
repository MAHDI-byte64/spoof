# Changelog

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
