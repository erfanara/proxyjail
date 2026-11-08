use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender},
        Arc,
    },
    time::Duration,
};

use proxyjail_core::EbpfEvent;

use super::message::RuntimeMessage;

const EVENT_RECV_INTERVAL: Duration = Duration::from_millis(100);

pub(super) fn forward_events(
    event_rx: Receiver<EbpfEvent>,
    tx: Sender<RuntimeMessage>,
    stopping: Arc<AtomicBool>,
) {
    while !stopping.load(Ordering::Acquire) {
        match event_rx.recv_timeout(EVENT_RECV_INTERVAL) {
            Ok(event) => {
                if tx.send(RuntimeMessage::EbpfEvent(event)).is_err() {
                    break;
                }
            }

            Err(RecvTimeoutError::Timeout) => {}

            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}