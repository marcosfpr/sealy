use std::ffi::c_void;
use std::ptr::null_mut;

use crate::bindgen;
use crate::error::*;
use crate::{Context, Plaintext};

/// Provides functionality for CRT batching. If the polynomial modulus degree is N, and
pub struct CKKSEncoder<'a> {
	handle: *mut c_void,
	ctx: &'a Context,
}

unsafe impl Sync for CKKSEncoder<'_> {}
unsafe impl Send for CKKSEncoder<'_> {}

impl<'a> CKKSEncoder<'a> {
	/// Creates a CKKS encoder. It is necessary that the encryption parameters
	/// given through the SEALContext object support it.
	///
	/// # Params
	///  * `ctx` - The Context
	pub fn new(ctx: &Context) -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		convert_seal_error(unsafe { bindgen::CKKSEncoder_Create(ctx.get_handle(), &mut handle) })?;

		Ok(Self {
			handle,
			ctx,
		})
	}

	/// Creates a plaintext from a given matrix.
	///
	/// The matrix's elements are of type `u64`.
	///
	///  * `data` - The `2xN` matrix of integers modulo plaintext modulus to batch
	pub fn encode_unsigned(
		&self,
		data: &[f64],
	) -> Result<Plaintext> {
		let plaintext = Plaintext::new()?;

		let mut parms_id = self.ctx.get_parms_id();
		let scale;
		let pool;

		// I pinky promise SEAL won't mutate data, the C bindings just aren't
		// const correct.
		convert_seal_error(unsafe {
			bindgen::CKKSEncoder_Encode1(
				self.handle,
				data.len() as u64,
				data.as_ptr() as *mut f64,
				_,
				_,
				plaintext.get_handle(),
				_,
			)
		})?;

		Ok(plaintext)
	}
}
