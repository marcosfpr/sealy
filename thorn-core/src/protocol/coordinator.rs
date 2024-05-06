//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.

use super::autogen::thorn_proto;

/// The [`CoordinatorClient`] is the main entry point for interacting with the thorn protocol.
/// It is used to aggregate messages from the servers.
pub use thorn_proto::coordinator_client::CoordinatorClient;

/// The [`CoordinatorServer`] is used to implement the coordinator for the thorn protocol.
pub use thorn_proto::coordinator_server::CoordinatorServer;

/// A server message to be sent to the coordinator.
pub use thorn_proto::ServerMessage;

/// A client message to be sent to the coordinator.
pub use thorn_proto::ClientMessage;

/// A status code for the messages.
pub use thorn_proto::Code;

/// A status for the messages.
pub use thorn_proto::Status;

/// The reason of an error.
pub use thorn_proto::Reason;

/// The parameters of a model.
pub use thorn_proto::Parameters;

/// A scalar value.
pub use thorn_proto::Scalar;
