use crate::Result;

/// Represents the type of compression used in the serialization.
#[allow(unused)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
	None = 0,
	ZLib = 1,
	ZStd = 2,
}

/// A trait for converting objects into byte arrays.
pub trait ToBytes {
	/// Returns the object as a byte array.
	fn as_bytes(&self) -> Result<Vec<u8>>;
}

/// A trait for converting data from a byte slice under a given SEAL context.
pub trait FromBytes {
	/// State used to deserialize an object from bytes.
	type State;
	/// Deserialize an object from the given bytes using the given
	/// state.
	fn from_bytes(
		state: &Self::State,
		bytes: &[u8],
	) -> Result<Self>
	where
		Self: Sized;
}
