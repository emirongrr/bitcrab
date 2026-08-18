use std::fmt;

/// Bitcoin Core: `DEFAULT_MAX_PEER_CONNECTIONS` in `src/net.h`.
pub const DEFAULT_MAX_PEER_CONNECTIONS: usize = 125;
/// Bitcoin Core: `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`.
pub const MAX_OUTBOUND_FULL_RELAY_CONNECTIONS: usize = 8;
/// Bitcoin Core: `MAX_BLOCK_RELAY_ONLY_CONNECTIONS`.
pub const MAX_BLOCK_RELAY_ONLY_CONNECTIONS: usize = 2;
/// Bitcoin Core: `MAX_FEELER_CONNECTIONS`.
pub const MAX_FEELER_CONNECTIONS: usize = 1;
/// Normal inbound capacity after reserving automatic persistent outbound slots.
pub const MAX_INBOUND_CONNECTIONS: usize = DEFAULT_MAX_PEER_CONNECTIONS
    - MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
    - MAX_BLOCK_RELAY_ONLY_CONNECTIONS;

/// Defines the topological intent and role of a P2P connection.
///
/// Bitcoin Core: ConnectionType (src/net.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionType {
    /// Inbound connection from an external peer
    Inbound,

    /// Standard bidirectional outbound connection. Relays blocks and transactions.
    #[default]
    OutboundFullRelay,

    /// Block-relay-only outbound connection. Does not participate in transaction or address gossip.
    /// Used for eclipse/inference attack mitigation.
    BlockRelayOnly,

    /// Short-lived connection strictly to test if an address is reachable.
    /// Disconnects immediately after version exchange.
    Feeler,
}

impl ConnectionType {
    /// Returns true if this connection should announce and request transactions.
    pub fn is_tx_relay_connection(&self) -> bool {
        match self {
            ConnectionType::Inbound | ConnectionType::OutboundFullRelay => true,
            ConnectionType::BlockRelayOnly | ConnectionType::Feeler => false,
        }
    }

    /// Returns true if this is an ephemeral connection that should be closed quickly
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, ConnectionType::Feeler)
    }

    pub fn is_outbound(&self) -> bool {
        !matches!(self, ConnectionType::Inbound)
    }
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionType::Inbound => write!(f, "inbound"),
            ConnectionType::OutboundFullRelay => write!(f, "outbound-full-relay"),
            ConnectionType::BlockRelayOnly => write!(f, "block-relay-only"),
            ConnectionType::Feeler => write!(f, "feeler"),
        }
    }
}
