#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate provides wrappers for Micorosft's SEAL Homomorphic encryption library.
//!
//! # Notes
//! All types in this crate implement Sync/Send. So long as you never dereference the
//! internal handle on any type after it has been dropped, these traits
//! should safely hold. The internal handles should be of little use to you anyways.
//!
//! This crate intentionally omits more esoteric use cases to streamline the API and
//! is currently incomplete (e.g. CKKS is not currently supported). If any underlying
//! SEAL API you care about is missing, please add it in a pull request or file
//! an [issue](https://github.com/Sunscreen-tech/Sunscreen/issues).

#![warn(missing_docs)]

#[cfg(not(target_arch = "wasm32"))]
extern crate link_cplusplus;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod bindgen {
	use std::os::raw::c_long;

	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

	pub const E_OK: c_long = 0x0;
	pub const E_POINTER: c_long = 0x80004003u32 as c_long;
	pub const E_INVALIDARG: c_long = 0x80070057u32 as c_long;
	pub const E_OUTOFMEMORY: c_long = 0x8007000Eu32 as c_long;
	pub const E_UNEXPECTED: c_long = 0x8000FFFFu32 as c_long;
	pub const COR_E_IO: c_long = 0x80131620u32 as c_long;
	pub const COR_E_INVALIDOPERATION: c_long = 0x80131509u32 as c_long;
}

mod serialization {
	#[repr(u8)]
	pub enum CompressionType {
		// None = 0,
		// ZLib = 1,
		ZStd = 2,
	}
}

mod batch;
mod ciphertext;
mod context;
mod context_data;
mod decryptor;
mod encoder;
mod encryptor;
mod error;
mod evaluator;
mod key_generator;
mod memory;
mod modulus;
mod parameters;
mod plaintext;
mod poly_array;

pub use batch::Batch;
pub use ciphertext::Ciphertext;
pub use context::Context;
pub use context_data::ContextData;
pub use decryptor::{batch::BatchDecryptor, Decryptor};
pub use encoder::batch::BatchEncoder;
pub use encoder::bfv::{BFVDecimalEncoder, BFVEncoder};
pub use encoder::ckks::CKKSEncoder;
pub use encoder::Encoder;
pub use encryptor::{
	batch::BatchEncryptor, marker as enc_marker, Asym, AsymmetricComponents, AsymmetricEncryptor,
	Encryptor, Sym, SymAsym, SymmetricComponents, SymmetricEncryptor,
};
pub use error::{Error, Result};
pub use evaluator::batch::BatchEvaluator;
pub use evaluator::bfv::BFVEvaluator;
pub use evaluator::ckks::CKKSEvaluator;
pub use evaluator::Evaluator;
pub use key_generator::{GaloisKeys, KeyGenerator, PublicKey, RelinearizationKeys, SecretKey};
pub use memory::MemoryPool;
pub use modulus::{CoefficientModulus, Modulus, PlainModulus, SecurityLevel};
pub use parameters::*;
pub use plaintext::Plaintext;
pub use poly_array::PolynomialArray;

/// A trait for converting objects into byte arrays.
pub trait ToBytes {
	/// Returns the object as a byte array.
	fn as_bytes(&self) -> Result<Vec<u8>>;
}

/// A trait for converting data from a byte slice under a given SEAL context.
pub trait FromBytes {
	/// Deserialize an object from the given bytes using the given
	/// context.
	fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self>
	where
		Self: Sized;
}
