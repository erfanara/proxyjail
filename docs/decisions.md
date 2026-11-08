- why not using tokio? cause it's overkill.

## eBPF event contract

`proxyjail-core` defines the userspace event:

```rust
pub struct EbpfEvent {
    pub pid_tgid: u64,
    pub client: SocketAddr,
    pub original_destination: SocketAddr,
}
```

The ring-buffer ABI expected by `proxyjail-ebpf` is documented in
`crates/proxyjail-ebpf/bpf/event.h` and `crates/proxyjail-ebpf/bpf/README.md`. It is a
24-byte record:

- `pid_tgid`: native-endian `u64` at offset 0
- `client_ip`: network-order IPv4 at offset 8
- `client_port`: network-order port at offset 12
- 2 bytes padding
- `original_ip`: network-order IPv4 at offset 16
- `original_port`: network-order port at offset 20
- 2 bytes tail padding

The `client` endpoint **must exactly match** the address returned by
`TcpStream::peer_addr()` on the accepted local TCP connection. The original
16-byte event containing only PID and original destination is not enough for
the matching strategy implemented here. Your BPF program must reliably
populate the client tuple before publishing the event. Do not assume the
source port is available in the initial cgroup `connect4` hook without
verifying the hook's socket state and the exact endpoint seen after any NAT or
redirection.
