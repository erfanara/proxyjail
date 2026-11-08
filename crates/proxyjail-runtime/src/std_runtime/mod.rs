mod config;
mod connection;
mod coordinator;
mod event_forwarder;
mod listener;
mod message;
mod relay;

pub use config::StdRuntimeConfig;

use std::{
    io,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
};

use proxyjail_core::EbpfEvent;

pub fn run(
    config: StdRuntimeConfig,
    event_rx: Receiver<EbpfEvent>,
) -> io::Result<()> {
    config.validate()?;

    let listener = TcpListener::bind(config.listen_addr)?;
    listener.set_nonblocking(true)?;

    println!("Proxy listener ready on {}", config.listen_addr);

    let (message_tx, message_rx) = mpsc::channel();
    let stopping = Arc::new(AtomicBool::new(false));

    // Start TCP listener thread.
    let accept_thread = {
        let tx = message_tx.clone();
        let worker_stopping = Arc::clone(&stopping);

        thread::Builder::new()
            .name("proxy-accept".into())
            .spawn(move || {
                listener::accept_loop(listener, tx, worker_stopping);
            })?
    };

    // Forward eBPF events to the coordinator.
    let event_thread = {
        let tx = message_tx.clone();
        let worker_stopping = Arc::clone(&stopping);

        match thread::Builder::new()
            .name("proxy-event-forwarder".into())
            .spawn(move || {
                event_forwarder::forward_events(
                    event_rx,
                    tx,
                    worker_stopping,
                );
            })
        {
            Ok(handle) => handle,

            Err(err) => {
                stopping.store(true, Ordering::Release);
                let _ = accept_thread.join();

                return Err(err);
            }
        }
    };

    drop(message_tx);

    // Run coordinator on the current thread.
    let result = coordinator::run(&config, message_rx);

    // Stop background workers.
    stopping.store(true, Ordering::Release);

    let accept_join = accept_thread.join();
    let event_join = event_thread.join();

    if accept_join.is_err() || event_join.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "a proxy runtime worker thread panicked",
        ));
    }

    result
}