use std::ffi::c_int;
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::bindgen;
use crate::error::*;
use crate::ContextData;
use crate::EncryptionParameters;
use crate::SecurityLevel;

/// Performs sanity checks (validation) and pre-computations for a given set of encryption
/// parameters. While the EncryptionParameters class is intended to be a light-weight class
/// to store the encryption parameters, the SEALContext class is a heavy-weight class that
/// is constructed from a given set of encryption parameters. It validates the parameters
/// for correctness, evaluates their properties, and performs and stores the results of
/// several costly pre-computations.
///
/// After the user has set at least the PolyModulus, CoeffModulus, and PlainModulus
/// parameters in a given EncryptionParameters instance, the parameters can be validated
/// for correctness and functionality by constructing an instance of SEALContext. The
/// constructor of SEALContext does all of its work automatically, and concludes by
/// constructing and storing an instance of the EncryptionParameterQualifiers class, with
/// its flags set according to the properties of the given parameters. If the created
/// instance of EncryptionParameterQualifiers has the ParametersSet flag set to true, the
/// given parameter set has been deemed valid and is ready to be used. If the parameters
/// were for some reason not appropriately set, the ParametersSet flag will be false,
/// and a new SEALContext will have to be created after the parameters are corrected.
///
/// By default, SEALContext creates a chain of SEALContext.ContextData instances. The
/// first one in the chain corresponds to special encryption parameters that are reserved
/// to be used by the various key classes (PrivateKey, PublicKey, etc.). These are the
/// exact same encryption parameters that are created by the user and passed to the
/// constructor of SEALContext. The properties KeyContextData and KeyParmsId return the
/// ContextData and the ParmsId corresponding to these special parameters. The rest of the
/// ContextData instances in the chain correspond to encryption parameters that are derived
/// from the first encryption parameters by always removing the last one of the moduli in
/// the CoeffModulus, until the resulting parameters are no longer valid, e.g., there are
/// no more primes left. These derived encryption parameters are used by ciphertexts and
/// plaintexts and their respective ContextData can be accessed through the
/// GetContextData(ParmsId) function. The properties FirstContextData and LastContextData
/// return the ContextData corresponding to the first and the last set of parameters in
/// the "data" part of the chain, i.e., the second and the last element in the full chain.
/// The chain is a doubly linked list and is referred to as the modulus switching chain.
pub struct Context {
	pub(crate) handle: *mut c_void,
}

unsafe impl Sync for Context {}
unsafe impl Send for Context {}

impl Context {
	/// Creates an instance of SEALContext and performs several pre-computations
	/// on the given EncryptionParameters.
	///
	/// * `params` - The encryption parameters.
	/// * `expand_mod_chain` - Determines whether the modulus switching chain
	/// should be created.
	/// * `security_level` - Determines whether a specific security level should be
	/// enforced according to HomomorphicEncryption.org security standard.
	pub fn new(
		params: &EncryptionParameters, expand_mod_chain: bool, security_level: SecurityLevel,
	) -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		convert_seal_error(unsafe {
			bindgen::SEALContext_Create(
				params.get_handle(),
				expand_mod_chain,
				security_level as c_int,
				&mut handle,
			)
		})?;

		Ok(Context {
			handle,
		})
	}

	/// Creates an instance of SEALContext and performs several pre-computations
	/// on the given EncryptionParameters. This function explicitly allows insecure parameters,
	/// and is only for testing!
	///
	/// * `params` - The encryption parameters.
	/// * `expand_mod_chain` - Determines whether the modulus switching chain
	/// should be created.
	#[cfg(feature = "insecure-params")]
	pub fn new_insecure(params: &EncryptionParameters, expand_mod_chain: bool) -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		convert_seal_error(unsafe {
			bindgen::SEALContext_Create(params.get_handle(), expand_mod_chain, 0, &mut handle)
		})?;

		Ok(Context {
			handle,
		})
	}

	/// Returns handle to the underlying SEAL object.
	pub fn get_handle(&self) -> *mut c_void {
		self.handle
	}

	/// Returns the key ContextData in the modulus switching chain.
	pub fn get_key_parms_id(&self) -> Result<Vec<u64>> {
		let mut parms_id: Vec<u64> =
			Vec::with_capacity(EncryptionParameters::block_size() as usize);
		convert_seal_error(unsafe {
			let parms_id_ptr = parms_id.as_mut_ptr();
			bindgen::SEALContext_KeyParmsId(self.handle, parms_id_ptr)
		})?;
		unsafe { parms_id.set_len(4) };
		Ok(parms_id)
	}

	/// Returns the last ContextData in the modulus switching chain.
	pub fn get_last_parms_id(&self) -> Result<Vec<u64>> {
		let mut parms_id: Vec<u64> =
			Vec::with_capacity(EncryptionParameters::block_size() as usize);
		convert_seal_error(unsafe {
			let parms_id_ptr = parms_id.as_mut_ptr();
			bindgen::SEALContext_LastParmsId(self.handle, parms_id_ptr)
		})?;
		unsafe { parms_id.set_len(EncryptionParameters::block_size() as usize) };
		Ok(parms_id)
	}

	/// Returns the first ContextData in the modulus switching chain.
	pub fn get_first_parms_id(&self) -> Result<Vec<u64>> {
		let mut parms_id: Vec<u64> =
			Vec::with_capacity(EncryptionParameters::block_size() as usize);
		convert_seal_error(unsafe {
			let parms_id_ptr = parms_id.as_mut_ptr();
			bindgen::SEALContext_FirstParmsId(self.handle, parms_id_ptr)
		})?;
		unsafe { parms_id.set_len(EncryptionParameters::block_size() as usize) };
		Ok(parms_id)
	}

	/// Returns the ContextData given a parms_id.
	pub fn get_context_data(&self, parms_id: &[u64]) -> Result<ContextData> {
		let mut context_data: *mut c_void = null_mut();

		convert_seal_error(unsafe {
			let mut parms_id = parms_id.to_vec();
			let parms_id_ptr = parms_id.as_mut_ptr();
			bindgen::SEALContext_GetContextData(self.handle, parms_id_ptr, &mut context_data)
		})?;

		if context_data.is_null() {
			return Err(Error::InvalidPointer);
		}

		Ok(ContextData::new(context_data))
	}

	/// Returns the first ContextData in the modulus switching chain.
	pub fn get_first_context_data(&self) -> Result<ContextData> {
		let mut context_data: *mut c_void = null_mut();

		convert_seal_error(unsafe {
			bindgen::SEALContext_FirstContextData(self.handle, &mut context_data)
		})?;

		if context_data.is_null() {
			return Err(Error::InvalidPointer);
		}

		Ok(ContextData::new(context_data))
	}

	/// Returns the last ContextData in the modulus switching chain.
	pub fn get_last_context_data(&self) -> Result<ContextData> {
		let mut context_data: *mut c_void = null_mut();

		convert_seal_error(unsafe {
			bindgen::SEALContext_LastContextData(self.handle, &mut context_data)
		})?;

		if context_data.is_null() {
			return Err(Error::InvalidPointer);
		}

		Ok(ContextData::new(context_data))
	}
}

impl Drop for Context {
	fn drop(&mut self) {
		convert_seal_error(unsafe { bindgen::SEALContext_Destroy(self.handle) })
			.expect("Internal error in Context::drop().");
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn can_create_and_drop_context() {
		let params = BfvEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D1024)
			.set_coefficient_modulus(
				CoefficientModulus::create(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus_u64(1234)
			.build()
			.unwrap();

		let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

		std::mem::drop(ctx);
	}
}
