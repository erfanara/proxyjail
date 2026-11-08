use std::{
    io,
    net::SocketAddr,
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct StdRuntimeConfig {
    pub listen_addr: SocketAddr,
    pub connect_timeout: Duration,
    pub pending_timeout: Duration,
    pub cleanup_interval: Duration,
}

impl Default for StdRuntimeConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 10000)),
            connect_timeout: Duration::from_secs(5),
            pending_timeout: Duration::from_secs(10),
            cleanup_interval: Duration::from_millis(250),
        }
    }
}

impl StdRuntimeConfig {
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.connect_timeout.is_zero()
            || self.pending_timeout.is_zero()
            || self.cleanup_interval.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeouts and cleanup_interval must be non-zero",
            ));
        }

        Ok(())
    }
}