use std::{
    convert::TryInto,
    fs::File,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::mpsc::Sender,
    time::Duration,
};

use anyhow::{Context, Result};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};

use proxyjail_core::EbpfEvent;

// Generated from the BPF object named `redirect`.
mod redirect {
    include!(concat!(env!("OUT_DIR"), "/redirect_cgroup.skel.rs"));
}

use redirect::*;

/// Configuration for the blocking libbpf ring-buffer poller.
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Cgroup v2 directory to which the cgroup programs are attached.
    pub cgroup_path: PathBuf,
    /// Maximum time spent in one ring-buffer poll call before returning.
    pub poll_interval: Duration,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            cgroup_path: PathBuf::from("/sys/fs/cgroup/ebpf-demo"),
            poll_interval: Duration::from_millis(100),
        }
    }
}

// ABI shared with the BPF program in bpf/event.h.
// C layout: u64, be32, be16, 2-byte padding, be32, be16, 2-byte tail padding.
const EVENT_SIZE: usize = 24;

/// Load and attach the redirect programs, then publish decoded ring-buffer
/// events to the proxy runtime.
///
/// This function blocks while polling the ring buffer. Run it on a dedicated
/// OS thread; do not call it from a latency-sensitive thread.
pub fn run(config: EbpfConfig, event_tx: Sender<EbpfEvent>) -> Result<()> {
    if config.poll_interval.is_zero() {
        anyhow::bail!("poll_interval must be non-zero");
    }

    let builder = RedirectCgroupSkelBuilder::default();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    // Keep the cgroup file descriptor alive while the attached links exist.
    let cgroup = File::open(&config.cgroup_path)
        .with_context(|| format!("opening cgroup {}", config.cgroup_path.display()))?;
    let cgroup_fd = cgroup.as_raw_fd();

    let progs = &mut skel.progs;
    let _connect4 = progs
        .connect4
        .attach_cgroup(cgroup_fd)
        .context("attaching connect4 cgroup program")?;
    let _getpeername4 = progs
        .getpeername4
        .attach_cgroup(cgroup_fd)
        .context("attaching getpeername4 cgroup program")?;
    let _sockops = progs
        .proxy_sockops
        .attach_cgroup(cgroup_fd)
        .context("attaching sockops cgroup program")?;

    let mut ring_buffer_builder = RingBufferBuilder::new();
    ring_buffer_builder.add(&skel.maps.events, move |data| {
        let Some(event) = parse_event(data) else {
            eprintln!("Ignoring malformed eBPF event ({} bytes)", data.len());
            return 0;
        };

        match event_tx.send(event) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("Proxy runtime receiver disconnected: {err}");
                // A negative callback result stops ring-buffer consumption.
                -1
            }
        }
    })?;

    let ring_buffer = ring_buffer_builder.build()?;

    println!(
        "eBPF programs attached to {}; polling ring buffer",
        config.cgroup_path.display()
    );

    loop {
        ring_buffer.poll(config.poll_interval)?;
    }
}

/// Decode the fixed-size event emitted by the BPF program.
///
/// The source endpoint must be the endpoint visible to the proxy listener,
/// such that it matches `TcpStream::peer_addr()` exactly.
fn parse_event(data: &[u8]) -> Option<EbpfEvent> {
    if data.len() < EVENT_SIZE {
        return None;
    }

    let pid_tgid = u64::from_ne_bytes(data[0..8].try_into().ok()?);

    let client_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&data[8..12]).ok()?);
    let client_port = u16::from_be_bytes(data[12..14].try_into().ok()?);

    // Bytes 14..16 are ABI padding.
    let original_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&data[16..20]).ok()?);
    let original_port = u16::from_be_bytes(data[20..22].try_into().ok()?);

    Some(EbpfEvent {
        pid_tgid,
        client: SocketAddr::V4(SocketAddrV4::new(client_ip, client_port)),
        original_destination: SocketAddr::V4(SocketAddrV4::new(
            original_ip,
            original_port,
        )),
    })
}
