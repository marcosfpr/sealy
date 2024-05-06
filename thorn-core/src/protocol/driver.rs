//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
use super::autogen::thorn_proto;

/// The [`DriverClient`] is the main entry point for interacting with the thorn protocol.
/// It is used to create a [`Fleet`] and to interact with the [`Coordinator`].
pub use thorn_proto::driver_client::DriverClient;

/// The [`DriverServer`] is used to implement the thorn protocol.
pub use thorn_proto::driver_server::DriverServer;

/// The request to create a new run.
pub use thorn_proto::CreateRunRequest;

/// The response to a request to create a new run.
pub use thorn_proto::CreateRunResponse;

/// The request to push a new task in the network.
pub use thorn_proto::PushTaskInsRequest;

/// The response to a request to push a new task in the network.
pub use thorn_proto::PushTaskInsResponse;

/// The request to pull a task from the network.
pub use thorn_proto::PullTaskResRequest;

/// The response to a request to pull a task from the network.
pub use thorn_proto::PullTaskResResponse;
