use crate::{Error, Plaintext};

/// BFV encoder.
pub mod bfv;

/// CKKS encoder.
pub mod ckks;

pub trait Encoder<T> {
	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	fn encode(&self, data: &T) -> Result<Plaintext, Error>;

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `plaintext` - The plaintext to decode.
	///
	/// # Returns
	/// The decoded data.
	fn decode(&self, plaintext: &Plaintext) -> Result<T, Error>;
}
