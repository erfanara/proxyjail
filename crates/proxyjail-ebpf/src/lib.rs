//! eBPF event producer for the proxy workspace.
//!
//! The libbpf-backed loader is opt-in because it requires Linux, libbpf build
//! dependencies, and the generated `redirect_cgroup.skel.rs` skeleton.

#[cfg(feature = "libbpf")]
mod libbpf;

#[cfg(feature = "libbpf")]
pub use libbpf::{run, EbpfConfig};
