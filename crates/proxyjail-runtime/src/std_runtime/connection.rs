use std::{
    io,
    net::TcpStream,
    thread,
    time::Duration,
};

use proxyjail_core::MatchedConnection;

use super::relay;

pub(super) fn dispatch(
    matched: MatchedConnection<TcpStream>,
    connect_timeout: Duration,
) -> io::Result<()> {
    let peer_addr = matched.peer_addr;
    let destination = matched.event.original_destination;
    let pid_tgid = matched.event.pid_tgid;

    thread::Builder::new()
        .name(format!("proxyjail-connection-{peer_addr}"))
        .spawn(move || {
            println!(
                "Matched client {peer_addr} (pid/tgid={pid_tgid}); connecting to {destination}"
            );

            match TcpStream::connect_timeout(
                &destination,
                connect_timeout,
            ) {
                Ok(upstream) => {
                    if let Err(err) = relay::relay(
                        matched.stream,
                        upstream,
                    ) {
                        eprintln!(
                            "Relay failed for {peer_addr} -> {destination}: {err}"
                        );
                    }
                }

                Err(err) => {
                    eprintln!(
                        "Upstream connection to {destination} failed: {err}"
                    );
                }
            }
        })?;

    Ok(())
}