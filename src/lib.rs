// The crate is published as `CandyTunnel` (PascalCase) for brand consistency;
// silence the conventional snake_case lint rather than rename every `use`.
#![allow(non_snake_case)]

// Use mimalloc as the global allocator for significantly faster multi-threaded
// allocation throughput compared to the system allocator.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod config;
pub mod packet;
pub mod raw_socket;
pub mod xor;
pub mod tunnel;
pub mod mux_fec;
pub mod quic;
pub mod app;
pub mod tun;
pub mod tun_bridge;
pub mod port_forward;
pub mod tuning;
pub mod logging;
pub mod check;
pub mod panel;
