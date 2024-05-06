//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
use super::autogen::thorn_proto;

/// A [`Node`] is a vertex in the graph of the federated network. It represents
/// a single entity that can produce or consume [`Task`]s.
pub use thorn_proto::Node;
