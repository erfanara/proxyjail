use std::net::SocketAddr;

/// A fully assembled observation of one outgoing connection.
///
/// `client` must be the exact peer endpoint that the local TCP listener will
/// observe through `TcpStream::peer_addr()`. It is the correlation key.
/// `original_destination` is where the proxy should open the upstream socket.
///
/// The eBPF layer should publish one `EbpfEvent` only after it has collected
/// enough information to populate both endpoints reliably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfEvent {
    pub pid_tgid: u64,
    pub client: SocketAddr,
    pub original_destination: SocketAddr,
}
