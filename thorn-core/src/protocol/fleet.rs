//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
use super::autogen::thorn_proto;

/// A request to create a new [`Node`] in the federated network.
pub use thorn_proto::CreateNodeRequest;

/// A response to a request to create a new [`Node`] in the federated network.
pub use thorn_proto::CreateNodeResponse;

/// A request to delete a [`Node`] from the federated network.
pub use thorn_proto::DeleteNodeRequest;

/// A response to a request to delete a [`Node`] from the federated network.
pub use thorn_proto::DeleteNodeResponse;

/// A ping request to a [`Node`] in the federated network.
pub use thorn_proto::PingRequest;

/// A ping response from a [`Node`] in the federated network.
pub use thorn_proto::PingResponse;

/// The [`FleetClient`] is used to interact with the fleet service in the federated network.
///
/// It provides a way to interact with the [`FleetServer`].
pub use thorn_proto::fleet_client::FleetClient;

/// The [`FleetServer`] is used to implement the fleet service in the federated network.
///
/// It provides a way to create, delete and ping nodes in the network.
pub use thorn_proto::fleet_server::FleetServer;

/// The [`Fleet`] trait is used to implement the fleet service in the federated network that will
/// be served by the [`FleetServer`] and accessed by the [`FleetClient`].
///
/// It provides a way to create, delete and ping nodes in the network.
pub use thorn_proto::fleet_server::Fleet;
