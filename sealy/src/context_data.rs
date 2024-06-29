use std::ffi::c_void;
use std::ptr::null_mut;

use crate::error::{convert_seal_error, Result};
use crate::{bindgen, EncryptionParameters};

///  ContextData holds context pre-computation data for a given set of encryption parameters.
#[derive(Debug)]
pub struct ContextData {
	/// The handle to the context data.
	handle: *mut c_void,
}

unsafe impl Sync for ContextData {}
unsafe impl Send for ContextData {}

impl ContextData {
	/// Creates a new [`ContextData`] with the given handle.
	pub fn new(handle: *mut c_void) -> Self {
		Self {
			handle,
		}
	}

	/// Returns the handle of this [`ContextData`].
	pub fn get_handle(&self) -> *mut c_void {
		self.handle
	}

	/// Returns the encryption parameters used to create the context data.
	pub fn get_encryption_parameters(&self) -> Result<EncryptionParameters> {
		let mut parms: *mut c_void = null_mut();

		convert_seal_error(unsafe { bindgen::ContextData_Parms(self.handle, &mut parms) })
			.expect("Internal error in ContextData::get_encryption_parameters().");

		Ok(EncryptionParameters {
			handle: parms,
		})
	}

	/// Returns the total number of primes in the coefficient modulus.
	pub fn get_total_coeff_modulus_bit_count(&self) -> Result<i32> {
		let mut bit_count: i32 = 0;

		convert_seal_error(unsafe {
			bindgen::ContextData_TotalCoeffModulusBitCount(self.handle, &mut bit_count)
		})?;

		Ok(bit_count)
	}
}
