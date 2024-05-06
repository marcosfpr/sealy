//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
pub use super::autogen::thorn_proto;

/// Errors that can occur when working with the thorn protocol.
///
/// It holds an error code and a reason message.
pub use thorn_proto::Error;
