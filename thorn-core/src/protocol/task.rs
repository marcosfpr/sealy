//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
use super::autogen::thorn_proto;

/// A [`Task`] corresponds to a single unit of work that is to be performed by a
/// [`Node`].
///
/// [`Task`]: thorn_proto::Task
/// [`Node`]: thorn_proto::Node
pub use thorn_proto::Task;

/// A [`TaskIns`] is a task request. It is used to request a [`Task`] in the
/// federated network.
pub use thorn_proto::TaskIns;

/// A [`TaskRes`] is a task response. It is used to respond to a [`TaskIns`] in
/// the federated network.
pub use thorn_proto::TaskRes;
