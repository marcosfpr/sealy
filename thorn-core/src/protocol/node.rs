pub mod thorn_proto {
	tonic::include_proto!("thorn");
}

/// A [`Node`] is a vertex in the graph of the federated network. It represents
/// a single entity that can produce or consume [`Task`]s.
pub use thorn_proto::Node;
