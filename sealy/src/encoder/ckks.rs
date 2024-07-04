use std::ffi::c_void;
use std::ptr::null_mut;

use crate::error::{convert_seal_error, Result};
use crate::{bindgen, Context, MemoryPool, Plaintext};

use super::{Encoder, SlotCount};

/// To create CKKS plaintexts we need a special encoder: there is no other way
/// to create them. The BatchEncoder cannot be used with the
/// CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
/// Plaintext objects, which can subsequently be encrypted. At a high level this
/// looks a lot like what BatchEncoder does for the BFV scheme, but the theory
/// behind it is completely different.
#[derive(Debug, Clone)]
pub struct CKKSEncoder {
	handle: *mut c_void,
	parms_id: Vec<u64>,
	scale: f64,
}

unsafe impl Sync for CKKSEncoder {}
unsafe impl Send for CKKSEncoder {}

impl CKKSEncoder {
	/// Creates a CKKSEncoder. It is necessary that the encryption parameters
	/// given through the SEALContext object support it.
	///
	/// * `ctx` - The Context
	pub fn new(ctx: &Context, scale: f64) -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		let parms_id = ctx.get_first_parms_id()?;

		convert_seal_error(unsafe { bindgen::CKKSEncoder_Create(ctx.get_handle(), &mut handle) })?;

		Ok(Self {
			handle,
			parms_id,
			scale,
		})
	}
}

impl SlotCount for CKKSEncoder {
	/// Returns the number of  slots in this encoder produces.
	fn get_slot_count(&self) -> usize {
		let mut count: u64 = 0;

		convert_seal_error(unsafe { bindgen::CKKSEncoder_SlotCount(self.handle, &mut count) })
			.expect("Internal error in BVTEncoder::get_slot_count().");

		count as usize
	}
}

impl Encoder<f64> for CKKSEncoder {
	type Encoded = Plaintext;
	/// Creates a plaintext from a given matrix of f64 data.
	///
	/// The floating-point coefficients of `data`
	/// will be scaled up by the parameter `scale'. This is necessary since even in
	/// the CKKS scheme the plaintext elements are fundamentally polynomials with
	/// integer coefficients. It is instructive to think of the scale as determining
	/// the bit-precision of the encoding; naturally it will affect the precision of
	/// the result.
	/// In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
	/// plain_modulus), so the scaled message must not get too close to the total size
	/// of coeff_modulus. In this case our coeff_modulus is quite large (200 bits) so
	/// we have little to worry about in this regard. For this simple example a 30-bit
	/// scale is more than enough.
	///
	///  * `data` - The `2xN` matrix of integers modulo plaintext modulus to batch
	///  * `scale` - The scaling factor
	///  * `context` - The context
	fn encode(&self, data: &[f64]) -> Result<Self::Encoded> {
		let mem = MemoryPool::new()?;

		let plaintext = Plaintext::new()?;

		// I pinky promise SEAL won't mutate data, the C bindings just aren't
		// const correct.
		convert_seal_error(unsafe {
			let mut parms_id = self.parms_id.clone();
			let parms_id_ptr = parms_id.as_mut_ptr();
			bindgen::CKKSEncoder_Encode1(
				self.handle,
				data.len() as u64,
				data.as_ptr() as *mut f64,
				parms_id_ptr,
				self.scale,
				plaintext.get_handle(),
				mem.get_handle(),
			)
		})?;

		Ok(plaintext)
	}

	fn decode(&self, plaintext: &Self::Encoded) -> Result<Vec<f64>> {
		let mut data = Vec::with_capacity(self.get_slot_count());
		let data_ptr = data.as_mut_ptr();
		let mut size: u64 = 0;

		// I pinky promise SEAL won't mutate data, the C bindings just aren't
		// const correct.
		convert_seal_error(unsafe {
			bindgen::CKKSEncoder_Decode1(
				self.handle,
				plaintext.get_handle(),
				&mut size,
				data_ptr,
				null_mut(),
			)
		})?;

		if data.capacity() < size as usize {
			panic!("Allocation overflow BVTEncoder::decode_unsigned");
		}

		unsafe {
			data.set_len(size as usize);
		}

		Ok(data)
	}
}

impl Drop for CKKSEncoder {
	fn drop(&mut self) {
		unsafe {
			bindgen::CKKSEncoder_Destroy(self.handle);
		}
	}
}
