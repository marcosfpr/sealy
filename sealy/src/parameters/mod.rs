use std::ffi::c_void;
use std::mem::forget;
use std::os::raw::c_ulong;
use std::ptr::null_mut;

use crate::bindgen::{self};
use crate::error::convert_seal_error;
use crate::error::Result;
use crate::serialization::CompressionType;
use crate::{try_seal, FromBytes, Modulus, ToBytes};

use serde::{Deserialize, Serialize};

/// BFV encryption parameters.
mod bfv;
pub use bfv::BFVEncryptionParametersBuilder;

/// CKKS encryption parameters.
mod ckks;
pub use ckks::CKKSEncryptionParametersBuilder;

/// The FHE scheme supported by SEAL.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemeType {
	/// None. Don't use this.
	None = 0x0,

	/// Brakerski/Fan-Vercauteren scheme
	Bfv = 0x1,

	/// Cheon-Kim-Kim-Song scheme
	Ckks = 0x2,
}

impl SchemeType {
	/// Converts a u8 to a SchemeType.
	pub fn from_u8(val: u8) -> Self {
		match val {
			0x0 => SchemeType::None,
			0x1 => SchemeType::Bfv,
			0x2 => SchemeType::Ckks,
			_ => panic!("Illegal scheme type"),
		}
	}

	/// Converts a SchemeType to a u8.
	pub fn to_u8(&self) -> u8 {
		*self as u8
	}
}

/// An immutable collection of parameters that defines an encryption scheme.
/// Use either the CKKSBuilder or BFVBuilder to create one of these. Once created,
/// these objects are effectively immutable.
///
/// Picking appropriate encryption parameters is essential to enable a particular
/// application while balancing performance and security. Some encryption settings
/// will not allow some inputs (e.g. attempting to encrypt a polynomial with more
/// coefficients than PolyModulus or larger coefficients than PlainModulus) or
/// support the desired computations (with noise growing too fast due to too large
/// PlainModulus and too small CoeffModulus).
///
/// The EncryptionParameters class maintains at all times a 256-bit hash of the
/// currently set encryption parameters called the ParmsId. This hash acts as
/// a unique identifier of the encryption parameters and is used by all further
/// objects created for these encryption parameters. The ParmsId is not intended
/// to be directly modified by the user but is used internally for pre-computation
/// data lookup and input validity checks. In modulus switching the user can use
/// the ParmsId to keep track of the chain of encryption parameters. The ParmsId is
/// not exposed in the public API of EncryptionParameters, but can be accessed
/// through the SEALContext.ContextData" class once the SEALContext
/// has been created.
///
/// Choosing inappropriate encryption parameters may lead to an encryption scheme
/// that is not secure, does not perform well, and/or does not support the input
/// and computation of the desired application. We highly recommend consulting an
/// expert in RLWE-based encryption when selecting parameters, as this is where
/// inexperienced users seem to most often make critical mistakes.
#[derive(Debug)]
pub struct EncryptionParameters {
	pub(crate) handle: *mut c_void,
}

unsafe impl Sync for EncryptionParameters {}
unsafe impl Send for EncryptionParameters {}

impl EncryptionParameters {
	/// Creates a new `EncryptionParameters` instance given a scheme type.
	pub fn new(scheme: SchemeType) -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		convert_seal_error(unsafe { bindgen::EncParams_Create1(scheme as u8, &mut handle) })?;

		Ok(Self {
			handle,
		})
	}

	/// The block size is always 4 for SEAL. That means every
	/// parms_id is a 4-tuple of 64-bit integers. representing the
	/// hash of the encryption parameters.
	pub const fn block_size() -> u8 {
		4
	}

	/// Returns the handle to the underlying SEAL object.
	pub fn get_handle(&self) -> *mut c_void {
		self.handle
	}

	/// Returns the polynomial degree of the underlying CKKS or BFV scheme.
	pub fn get_poly_modulus_degree(&self) -> u64 {
		let mut degree: u64 = 0;

		unsafe {
			convert_seal_error(bindgen::EncParams_GetPolyModulusDegree(
				self.handle,
				&mut degree,
			))
			.expect("Internal error");
		};

		degree
	}

	/// Get the underlying scheme.
	pub fn get_scheme(&self) -> SchemeType {
		let mut scheme: u8 = 0;

		unsafe {
			convert_seal_error(bindgen::EncParams_GetScheme(self.handle, &mut scheme))
				.expect("Internal error");
		};

		SchemeType::from_u8(scheme)
	}

	/// Returns the plain text modulus for the encryption scheme.
	pub fn get_plain_modulus(&self) -> Modulus {
		let mut borrowed_modulus = null_mut();

		unsafe {
			convert_seal_error(bindgen::EncParams_GetPlainModulus(
				self.handle,
				&mut borrowed_modulus,
			))
			.expect("Internal error")
		};

		let borrowed_modulus = unsafe { Modulus::new_unchecked_from_handle(borrowed_modulus) };

		// We don't own the modulus we were given, so copy one we do own
		// and don't drop the old one.
		let ret = borrowed_modulus.clone();
		forget(borrowed_modulus);

		ret
	}

	/// Returns the coefficient modulus for the encryption scheme.
	pub fn get_coefficient_modulus(&self) -> Vec<Modulus> {
		let mut len: u64 = 0;

		unsafe {
			convert_seal_error(bindgen::EncParams_GetCoeffModulus(
				self.handle,
				&mut len,
				null_mut(),
			))
			.expect("Internal error")
		};

		let mut borrowed_modulus = Vec::with_capacity(len as usize);
		let borrowed_modulus_ptr = borrowed_modulus.as_mut_ptr();

		unsafe {
			convert_seal_error(bindgen::EncParams_GetCoeffModulus(
				self.handle,
				&mut len,
				borrowed_modulus_ptr,
			))
			.expect("Internal error");

			borrowed_modulus.set_len(len as usize);
		};

		borrowed_modulus
			.iter()
			.map(|h| {
				let modulus = unsafe { Modulus::new_unchecked_from_handle(*h) };
				let ret = modulus.clone();

				forget(modulus);

				ret
			})
			.collect()
	}

	/// Returns the parms id.
	pub fn get_parms_id(&self) -> u64 {
		let mut parms_id: c_ulong = 0;

		unsafe {
			convert_seal_error(bindgen::EncParams_GetParmsId(self.handle, &mut parms_id))
				.expect("Internal error");
		}

		parms_id
	}

	/// Sets the polynomial modulus degree.
	pub fn set_coefficient_modulus(
		&mut self,
		modulus: Vec<Modulus>,
	) -> Result<()> {
		unsafe {
			let modulus_ref = modulus
				.iter()
				.map(|m| m.get_handle())
				.collect::<Vec<*mut c_void>>();

			let modulus_ptr = modulus_ref.as_ptr() as *mut *mut c_void;

			try_seal!(bindgen::EncParams_SetCoeffModulus(
				self.handle,
				modulus.len() as u64,
				modulus_ptr
			))
		}
	}

	/// Sets the polynomial modulus degree.
	pub fn set_poly_modulus_degree(
		&mut self,
		degree: u64,
	) -> Result<()> {
		convert_seal_error(unsafe { bindgen::EncParams_SetPolyModulusDegree(self.handle, degree) })
	}

	/// Sets the plain modulus as a [`Modulus`] instance.
	pub fn set_plain_modulus(
		&mut self,
		modulus: Modulus,
	) -> Result<()> {
		convert_seal_error(unsafe {
			bindgen::EncParams_SetPlainModulus1(self.handle, modulus.get_handle())
		})
	}

	/// Sets the plain modulus as a constant.
	pub fn set_plain_modulus_u64(
		&mut self,
		modulus: u64,
	) -> Result<()> {
		convert_seal_error(unsafe { bindgen::EncParams_SetPlainModulus2(self.handle, modulus) })
	}
}

/// The coefficient modulus is a list of distinct [`Modulus`] instances.
#[derive(Debug, PartialEq)]
pub enum CoefficientModulusType {
	/// The coefficient modulus is not set.
	NotSet,
	/// The coefficient modulus is defined as a list of distinct [`Modulus`] instances.
	Modulus(Vec<Modulus>),
}

/// The plain modulus is either a constant or a [`Modulus`] instance.
#[derive(Debug, PartialEq)]
pub enum PlainModulusType {
	/// The plain modulus is not set.
	NotSet,
	/// The plain modulus is defined as a constant.
	Constant(u64),
	/// The plain modulus is defined as a [`Modulus`] instance.
	Modulus(Modulus),
}

impl Drop for EncryptionParameters {
	fn drop(&mut self) {
		convert_seal_error(unsafe { bindgen::EncParams_Destroy(self.handle) })
			.expect("Internal error in EncryptionParameters::drop().");
	}
}

impl ToBytes for EncryptionParameters {
	fn as_bytes(&self) -> Result<Vec<u8>> {
		let mut num_bytes: i64 = 0;

		convert_seal_error(unsafe {
			bindgen::EncParams_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
		})?;

		let mut data: Vec<u8> = Vec::with_capacity(num_bytes as usize);
		let mut bytes_written: i64 = 0;

		convert_seal_error(unsafe {
			let data_ptr = data.as_mut_ptr();

			bindgen::EncParams_Save(
				self.handle,
				data_ptr,
				num_bytes as u64,
				CompressionType::ZStd as u8,
				&mut bytes_written,
			)
		})?;

		unsafe { data.set_len(bytes_written as usize) };

		Ok(data)
	}
}

impl FromBytes for EncryptionParameters {
	type State = SchemeType;
	fn from_bytes(
		scheme: &SchemeType,
		bytes: &[u8],
	) -> Result<Self> {
		let key = Self::new(*scheme)?;
		let mut bytes_read = 0;

		convert_seal_error(unsafe {
			bindgen::EncParams_Load(
				key.handle,
				bytes.as_ptr() as *mut u8,
				bytes.len() as u64,
				&mut bytes_read,
			)
		})?;

		Ok(key)
	}
}
