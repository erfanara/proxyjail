use std::{
    io,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::Duration,
};

use super::message::RuntimeMessage;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

pub(super) fn accept_loop(
    listener: TcpListener,
    tx: Sender<RuntimeMessage>,
    stopping: Arc<AtomicBool>,
) {
    while !stopping.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if tx
                    .send(RuntimeMessage::AcceptedConnection {
                        stream,
                        peer_addr,
                    })
                    .is_err()
                {
                    break;
                }
            }

            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_RETRY_DELAY);
            }

            Err(err) => {
                let _ = tx.send(RuntimeMessage::ListenerFailed(
                    err.to_string(),
                ));
                break;
            }
        }
    }
}