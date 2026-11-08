use std::{
    io::{self, copy},
    net::{Shutdown, TcpStream},
    thread,
};

pub(super) fn relay(
    client: TcpStream,
    upstream: TcpStream,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;

    let mut client_writer = client;
    let mut upstream_reader = upstream;

    // Client -> Upstream
    let upload_thread = thread::Builder::new()
        .name("proxyjail-client-to-upstream".into())
        .spawn(move || {
            match copy(
                &mut client_reader,
                &mut upstream_writer,
            ) {
                Ok(bytes_copied) => {
                    upstream_writer.shutdown(Shutdown::Write)?;
                    Ok(bytes_copied)
                }

                Err(err) => {
                    let _ = client_reader.shutdown(Shutdown::Both);
                    let _ = upstream_writer.shutdown(Shutdown::Both);

                    Err(err)
                }
            }
        })?;

    // Upstream -> Client
    let download_result = copy(
        &mut upstream_reader,
        &mut client_writer,
    );

    match &download_result {
        Ok(_) => {
            let _ = client_writer.shutdown(Shutdown::Write);
        }

        Err(_) => {
            let _ = client_writer.shutdown(Shutdown::Both);
            let _ = upstream_reader.shutdown(Shutdown::Both);
        }
    }

    let upload_result = upload_thread
        .join()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "upload relay thread panicked",
            )
        })?;

    download_result?;
    upload_result?;

    Ok(())
}