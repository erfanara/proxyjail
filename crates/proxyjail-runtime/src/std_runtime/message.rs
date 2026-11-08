use std::{
    net::{SocketAddr, TcpStream},
};

use proxyjail_core::EbpfEvent;

pub(super) enum RuntimeMessage {
    EbpfEvent(EbpfEvent),

    AcceptedConnection {
        stream: TcpStream,
        peer_addr: SocketAddr,
    },

    ListenerFailed(String),
}