use std::{
    io,
    net::SocketAddr,
    sync::mpsc,
    time::Duration,
};

use proxyjail_core::EbpfEvent;
use proxyjail_runtime::std_runtime::{self, StdRuntimeConfig};

#[cfg(feature = "ebpf")]
use std::{path::PathBuf, thread};

fn main() -> io::Result<()> {
    let (event_tx, event_rx) = mpsc::channel::<EbpfEvent>();

    #[cfg(feature = "ebpf")]
    {
        let cgroup_path = std::env::var_os("PROXY_EBPF_CGROUP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/ebpf-demo"));

        let ebpf_config = proxyjail_ebpf::EbpfConfig {
            cgroup_path,
            ..proxyjail_ebpf::EbpfConfig::default()
        };

        thread::Builder::new()
            .name("proxyjail-ebpf-poller".into())
            .spawn(move || {
                if let Err(err) = proxyjail_ebpf::run(ebpf_config, event_tx) {
                    eprintln!("eBPF poller failed: {err:#}");
                }
            })?;
    }

    // Without the `ebpf` feature this CLI is useful for developing/testing
    // the runtime, but it has no event producer and cannot match connections.
    #[cfg(not(feature = "ebpf"))]
    drop(event_tx);

    let config = StdRuntimeConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 10000)),
        connect_timeout: Duration::from_secs(5),
        pending_timeout: Duration::from_secs(10),
        cleanup_interval: Duration::from_millis(250),
    };

    std_runtime::run(config, event_rx)
}
