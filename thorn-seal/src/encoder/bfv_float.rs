/// Simple base suggestion for encoding float point numbers.
pub mod consts {
	#[allow(dead_code)]
	pub const DEFAULT_BASE: u64 = 1e6 as u64;
}

/// Float point numbers encoder for BFV encryption scheme.
///
/// It basically uses a base to encode the float point number
/// as an integer.
#[derive(Debug, Clone)]
pub struct BFVFloatEncoder {
	base: u64,
}

impl BFVFloatEncoder {
	/// Creates a new instance of BFVFloatEncoder.
	///
	/// * `base` - The base to encode the float point number.
	pub fn new(base: u64) -> Self {
		Self {
			base,
		}
	}

	/// Encodes a float point number as an integer.
	///
	/// * `value` - The float point number to encode.
	pub fn encode(
		&self,
		value: f64,
	) -> u64 {
		(value * self.base as f64).round() as u64
	}

	/// Decodes an integer to a float point number.
	///
	/// * `value` - The integer to decode.
	pub fn decode(
		&self,
		value: u64,
	) -> f64 {
		value as f64 / self.base as f64
	}

	/// Encodes a slice of float point numbers as integers.
	///
	/// * `values` - The slice of float point numbers to encode.
	pub fn encode_slice(
		&self,
		values: &[f64],
	) -> Vec<u64> {
		values.iter().map(|v| self.encode(*v)).collect()
	}

	/// Decodes a slice of integers to float point numbers.
	///
	/// * `values` - The slice of integers to decode.
	pub fn decode_slice(
		&self,
		values: &[u64],
	) -> Vec<f64> {
		values.iter().map(|v| self.decode(*v)).collect()
	}
}
