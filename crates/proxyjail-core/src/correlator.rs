use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::EbpfEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSide {
    EbpfEvent,
    TcpConnection,
}

pub struct MatchedConnection<C> {
    pub event: EbpfEvent,
    pub stream: C,
    pub peer_addr: SocketAddr,
}

pub enum CorrelationOutcome<C> {
    /// The item was saved until its counterpart arrives.
    Pending {
        key: SocketAddr,
        side: PendingSide,
    },
    /// Both observations are now available.
    Matched(MatchedConnection<C>),
    /// Another unmatched item with the same key was already pending.
    /// The duplicate item is dropped.
    Duplicate {
        key: SocketAddr,
        side: PendingSide,
    },
}

struct Pending<T> {
    value: T,
    since: Instant,
}

pub struct Correlator<C> {
    pending_events: HashMap<SocketAddr, Pending<EbpfEvent>>,
    pending_connections: HashMap<SocketAddr, Pending<C>>,
}

impl<C> Default for Correlator<C> {
    fn default() -> Self {
        Self {
            pending_events: HashMap::new(),
            pending_connections: HashMap::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ExpiredItems {
    pub events: Vec<SocketAddr>,
    pub connections: Vec<SocketAddr>,
}

impl<C> Correlator<C> {
    pub fn on_event(&mut self, event: EbpfEvent) -> CorrelationOutcome<C> {
        let key = event.client;

        if let Some(pending) = self.pending_connections.remove(&key) {
            return CorrelationOutcome::Matched(MatchedConnection {
                event,
                stream: pending.value,
                peer_addr: key,
            });
        }

        if self.pending_events.contains_key(&key) {
            return CorrelationOutcome::Duplicate {
                key,
                side: PendingSide::EbpfEvent,
            };
        }

        self.pending_events.insert(
            key,
            Pending {
                value: event,
                since: Instant::now(),
            },
        );

        CorrelationOutcome::Pending {
            key,
            side: PendingSide::EbpfEvent,
        }
    }

    pub fn on_connection(
        &mut self,
        stream: C,
        peer_addr: SocketAddr,
    ) -> CorrelationOutcome<C> {
        if let Some(pending) = self.pending_events.remove(&peer_addr) {
            return CorrelationOutcome::Matched(MatchedConnection {
                event: pending.value,
                stream,
                peer_addr,
            });
        }

        if self.pending_connections.contains_key(&peer_addr) {
            // `stream` is dropped here, closing the duplicate connection.
            return CorrelationOutcome::Duplicate {
                key: peer_addr,
                side: PendingSide::TcpConnection,
            };
        }

        self.pending_connections.insert(
            peer_addr,
            Pending {
                value: stream,
                since: Instant::now(),
            },
        );

        CorrelationOutcome::Pending {
            key: peer_addr,
            side: PendingSide::TcpConnection,
        }
    }

    /// Remove unmatched observations older than `ttl`.
    /// Removing a pending TCP connection drops its stream.
    pub fn expire(&mut self, now: Instant, ttl: Duration) -> ExpiredItems {
        let mut expired = ExpiredItems::default();

        self.pending_events.retain(|key, pending| {
            let keep = now.duration_since(pending.since) < ttl;
            if !keep {
                expired.events.push(*key);
            }
            keep
        });

        self.pending_connections.retain(|key, pending| {
            let keep = now.duration_since(pending.since) < ttl;
            if !keep {
                expired.connections.push(*key);
            }
            keep
        });

        expired
    }

    pub fn pending_counts(&self) -> (usize, usize) {
        (
            self.pending_events.len(),
            self.pending_connections.len(),
        )
    }
}
