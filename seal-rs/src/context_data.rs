use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::error::Result;
use crate::{bindgen, try_seal, EncryptionParameters};

///  ContextData holds context pre-computation data for a given set of encryption parameters.
#[derive(Debug)]
pub struct ContextData {
	/// The handle to the context data.
	handle: AtomicPtr<c_void>,
}

impl ContextData {
	/// Creates a new [`ContextData`] with the given handle.
	pub fn new(handle: *mut c_void) -> Self {
		Self {
			handle: AtomicPtr::new(handle),
		}
	}

	/// Returns the handle of this [`ContextData`].
	pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
		self.handle.load(Ordering::SeqCst)
	}

	/// Returns the encryption parameters used to create the context data.
	pub fn get_encryption_parameters(&self) -> Result<EncryptionParameters> {
		let mut parms: *mut c_void = null_mut();

		try_seal!(unsafe { bindgen::ContextData_Parms(self.get_handle(), &mut parms) })
			.expect("Internal error in ContextData::get_encryption_parameters().");

		Ok(EncryptionParameters {
			handle: parms,
		})
	}

	/// Returns the total number of primes in the coefficient modulus.
	pub fn get_total_coeff_modulus_bit_count(&self) -> Result<i32> {
		let mut bit_count: i32 = 0;

		try_seal!(unsafe {
			bindgen::ContextData_TotalCoeffModulusBitCount(self.get_handle(), &mut bit_count)
		})?;

		Ok(bit_count)
	}
}

impl Drop for ContextData {
	fn drop(&mut self) {
		try_seal!(unsafe { bindgen::ContextData_Destroy(self.get_handle()) })
			.expect("Internal error ContextData::drop().");
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn test_can_create_context_data() {
		let params = BFVEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D1024)
			.set_coefficient_modulus(
				CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus_u64(1234)
			.build()
			.unwrap();

		let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
		assert_eq!(ctx.get_security_level().unwrap(), SecurityLevel::TC128);

		let ctx_data = ctx.get_first_context_data().unwrap();
		let expected_params = ctx_data.get_encryption_parameters().unwrap();
		assert_eq!(expected_params.get_poly_modulus_degree(), 1024);
		assert_eq!(expected_params.get_scheme(), SchemeType::Bfv);
		assert_eq!(expected_params.get_plain_modulus().value(), 1234);
		assert_eq!(expected_params.get_coefficient_modulus().len(), 5);
	}
}
