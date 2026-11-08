use std::{
    io,
    net::TcpStream,
    sync::mpsc::{Receiver, RecvTimeoutError},
    time::Instant,
};

use proxyjail_core::{
    CorrelationOutcome,
    Correlator,
    PendingSide,
};

use super::{
    config::StdRuntimeConfig,
    connection,
    message::RuntimeMessage,
};

pub(super) fn run(
    config: &StdRuntimeConfig,
    rx: Receiver<RuntimeMessage>,
) -> io::Result<()> {
    let mut correlator: Correlator<TcpStream> = Correlator::default();

    loop {
        match rx.recv_timeout(config.cleanup_interval) {
            Ok(RuntimeMessage::EbpfEvent(event)) => {
                let outcome = correlator.on_event(event);
                handle_outcome(outcome, config)?;
            }

            Ok(RuntimeMessage::AcceptedConnection {
                stream,
                peer_addr,
            }) => {
                let outcome = correlator.on_connection(stream, peer_addr);
                handle_outcome(outcome, config)?;
            }

            Ok(RuntimeMessage::ListenerFailed(message)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    message,
                ));
            }

            Err(RecvTimeoutError::Timeout) => {}

            Err(RecvTimeoutError::Disconnected) => {
                return Ok(());
            }
        }

        // Expire unmatched observations.
        let expired = correlator.expire(
            Instant::now(),
            config.pending_timeout,
        );

        for key in expired.events {
            eprintln!(
                "Timed out waiting for TCP connection matching eBPF event: {key}"
            );
        }

        for key in expired.connections {
            eprintln!(
                "Timed out waiting for eBPF event matching TCP connection: {key}"
            );
        }
    }
}

fn handle_outcome(
    outcome: CorrelationOutcome<TcpStream>,
    config: &StdRuntimeConfig,
) -> io::Result<()> {
    match outcome {
        CorrelationOutcome::Pending { key, side } => {
            match side {
                PendingSide::EbpfEvent => {
                    println!(
                        "Waiting for TCP connection matching {key}"
                    );
                }

                PendingSide::TcpConnection => {
                    println!(
                        "Waiting for eBPF event matching {key}"
                    );
                }
            }
        }

        CorrelationOutcome::Duplicate { key, side } => {
            eprintln!(
                "Duplicate pending {side:?} for {key}; dropping duplicate"
            );
        }

        CorrelationOutcome::Matched(matched) => {
            connection::dispatch(matched, config.connect_timeout)?;
        }
    }

    Ok(())
}