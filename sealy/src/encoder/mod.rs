use crate::Error;

/// BFV encoder.
pub mod bfv;

/// CKKS encoder.
pub mod ckks;

/// An interface for encoding and decoding data.
pub trait Encoder<T>: SlotCount {
	/// The type of the encoded data.
	type Encoded;

	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	fn encode(&self, data: &[T]) -> Result<Self::Encoded, Error>;

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `encoded` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	fn decode(&self, encoded: &Self::Encoded) -> Result<Vec<T>, Error>;
}

/// A trait for objects that have a slot count.
pub trait SlotCount {
	/// Returns the number of slots in this encoder produces.
	fn get_slot_count(&self) -> usize;
}
