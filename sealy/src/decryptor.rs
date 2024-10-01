use std::{
	ffi::c_void,
	ptr::null_mut,
	sync::atomic::{AtomicPtr, Ordering},
};

use crate::{bindgen, error::Result, try_seal, Ciphertext, Context, Plaintext, SecretKey};

/// Decrypts Ciphertext objects into Plaintext objects. Constructing a Decryptor requires
/// a SEALContext with valid encryption parameters, and the secret key. The Decryptor is
/// also used to compute the invariant noise budget in a given ciphertext.
///
/// # NTT form (TODO)
/// When using the BFV scheme (SchemeType.BFV), all plaintext and ciphertexts should
/// remain by default in the usual coefficient representation, i.e. not in NTT form.
/// When using the CKKS scheme (SchemeType.CKKS), all plaintexts and ciphertexts
/// should remain by default in NTT form. We call these scheme-specific NTT states the
/// "default NTT form". Decryption requires the input ciphertexts to be in the default
/// NTT form, and will throw an exception if this is not the case.
pub struct Decryptor {
	handle: AtomicPtr<c_void>,
}

impl Decryptor {
	/// Creates a Decryptor instance initialized with the specified SEALContext
	/// and secret key.
	///
	/// The SEALContext
	/// The secret key
	pub fn new(
		ctx: &Context,
		secret_key: &SecretKey,
	) -> Result<Self> {
		let mut handle = null_mut();

		try_seal!(unsafe {
			bindgen::Decryptor_Create(ctx.get_handle(), secret_key.get_handle(), &mut handle)
		})?;

		Ok(Self {
			handle: AtomicPtr::new(handle),
		})
	}

	/// Returns the handle to the underlying SEAL object.
	pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
		self.handle.load(Ordering::SeqCst)
	}

	/// Decrypts a Ciphertext and stores the result in the destination parameter.
	///
	///  * `encrypted` - The ciphertext to decrypt.
	pub fn decrypt(
		&self,
		ciphertext: &Ciphertext,
	) -> Result<Plaintext> {
		let plaintext = Plaintext::new()?;

		try_seal!(unsafe {
			bindgen::Decryptor_Decrypt(
				self.get_handle(),
				ciphertext.get_handle(),
				plaintext.get_handle(),
			)
		})?;

		Ok(plaintext)
	}

	/// Computes the invariant noise budget (in bits) of a ciphertext. The invariant noise
	/// budget measures the amount of room there is for the noise to grow while ensuring
	/// correct decryptions. Dynamic memory allocations in the process are allocated from
	/// the memory pool pointed to by the given MemoryPoolHandle. This function works only
	/// with the BFV scheme.
	///
	/// # Invariant Noise Budget
	/// The invariant noise polynomial of a ciphertext is a rational coefficient polynomial,
	/// such that a ciphertext decrypts correctly as long as the coefficients of the invariant
	/// noise polynomial are of absolute value less than 1/2. Thus, we call the infinity-norm
	/// of the invariant noise polynomial the invariant noise, and for correct decryption require
	/// it to be less than 1/2. If v denotes the invariant noise, we define the invariant noise
	/// budget as -log2(2v). Thus, the invariant noise budget starts from some initial value,
	/// which depends on the encryption parameters, and decreases when computations are performed.
	/// When the budget reaches zero, the ciphertext becomes too noisy to decrypt correctly.
	///
	/// * `ciphertext` - The ciphertext for which to measure noise.
	pub fn invariant_noise_budget(
		&self,
		ciphertext: &Ciphertext,
	) -> Result<u32> {
		let mut noise: i32 = 0;

		try_seal!(unsafe {
			bindgen::Decryptor_InvariantNoiseBudget(
				self.get_handle(),
				ciphertext.get_handle(),
				&mut noise,
			)
		})?;

		Ok(noise as u32)
	}

	/// Computes the invariant noise of a ciphertext. The invariant noise is
	/// a value that increases with FHE operations. This function only works
	/// with the BFV scheme.
	///
	/// # Invariant Noise
	/// The invariant noise polynomial of a ciphertext is a rational * coefficient
	/// polynomial, such that a ciphertext decrypts correctly as long as the
	/// coefficients of the invariant noise polynomial are of absolute value less
	/// than 1/2. Thus, we call the infinity-norm of the invariant noise polynomial
	/// the invariant noise, and for correct decryption require it to be less than
	/// 1/2.
	pub fn invariant_noise(
		&self,
		ciphertext: &Ciphertext,
	) -> Result<f64> {
		let mut noise: f64 = 0f64;

		try_seal!(unsafe {
			bindgen::Decryptor_InvariantNoise(
				self.get_handle(),
				ciphertext.get_handle(),
				&mut noise,
			)
		})?;

		Ok(noise)
	}
}

impl Drop for Decryptor {
	fn drop(&mut self) {
		try_seal!(unsafe { bindgen::Decryptor_Destroy(self.get_handle()) })
			.expect("Internal error Decryptor::drop().");
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	use super::Decryptor;

	fn mk_ctx<F>(enc_modifier: F) -> Context
	where
		F: FnOnce(BFVEncryptionParametersBuilder) -> BFVEncryptionParametersBuilder,
	{
		let builder = BFVEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D8192)
			.set_coefficient_modulus(
				CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus_u64(1234);
		let params = enc_modifier(builder).build().unwrap();

		Context::new(&params, false, SecurityLevel::TC128).unwrap()
	}

	#[test]
	fn can_create_and_destroy_decryptor() {
		let params = BFVEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D8192)
			.set_coefficient_modulus(
				CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus_u64(1234)
			.build()
			.unwrap();

		let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
		let gen = KeyGenerator::new(&ctx).unwrap();

		let secret_key = gen.secret_key();
		let decryptor = Decryptor::new(&ctx, &secret_key);

		std::mem::drop(decryptor);
	}

	#[test]
	fn can_encrypt_and_decrypt_unsigned() {
		let ctx = mk_ctx(|b| {
			b.set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
		});
		let gen = KeyGenerator::new(&ctx).unwrap();

		let encoder = BFVEncoder::new(&ctx).unwrap();

		let mut data = vec![];

		for i in 0..encoder.get_slot_count() {
			data.push(i as u64)
		}

		let plaintext = encoder.encode_u64(&data).unwrap();

		let public_key = gen.create_public_key();
		let secret_key = gen.secret_key();

		let encryptor =
			Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();
		let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();

		// asymmetric test
		let ciphertext = encryptor.encrypt(&plaintext).unwrap();
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<u64> = encoder.decode_u64(&decrypted).unwrap();
		assert_eq!(data, data_2);

		// symmetric test
		let ciphertext = encryptor.encrypt_symmetric(&plaintext).unwrap();
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<u64> = encoder.decode_u64(&decrypted).unwrap();
		assert_eq!(data, data_2);
	}

	#[test]
	fn can_encrypt_and_decrypt_signed() {
		let ctx = mk_ctx(|b| {
			b.set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
		});
		let gen = KeyGenerator::new(&ctx).unwrap();

		let encoder = BFVEncoder::new(&ctx).unwrap();

		let mut data = vec![];

		for i in 0..encoder.get_slot_count() {
			data.push(encoder.get_slot_count() as i64 / 2i64 - i as i64)
		}

		let plaintext = encoder.encode_i64(&data).unwrap();

		let public_key = gen.create_public_key();
		let secret_key = gen.secret_key();

		let encryptor =
			Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();
		let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();

		// asymmetric test
		let ciphertext = encryptor.encrypt(&plaintext).unwrap();
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<i64> = encoder.decode_i64(&decrypted).unwrap();
		assert_eq!(data, data_2);

		// asymmetric test
		let ciphertext = encryptor.encrypt_symmetric(&plaintext).unwrap();
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<i64> = encoder.decode_i64(&decrypted).unwrap();
		assert_eq!(data, data_2);
	}

	#[test]
	fn can_encrypt_and_decrypt_from_return_components() {
		let ctx = mk_ctx(|b| {
			b.set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
		});
		let gen = KeyGenerator::new(&ctx).unwrap();

		let encoder = BFVEncoder::new(&ctx).unwrap();

		let mut data = vec![];

		for i in 0..encoder.get_slot_count() {
			data.push(i as u64);
		}

		let plaintext = encoder.encode_u64(&data).unwrap();

		let public_key = gen.create_public_key();
		let secret_key = gen.secret_key();

		let encryptor =
			Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();
		let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();

		// asymmetric test
		let ciphertext = encryptor.encrypt_return_components(&plaintext).unwrap().0;
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<u64> = encoder.decode_u64(&decrypted).unwrap();
		assert_eq!(data, data_2);

		// asymmetric test
		let ciphertext = encryptor
			.encrypt_symmetric_return_components(&plaintext)
			.unwrap()
			.0;
		let decrypted = decryptor.decrypt(&ciphertext).unwrap();
		let data_2: Vec<u64> = encoder.decode_u64(&decrypted).unwrap();
		assert_eq!(data, data_2);
	}

	#[cfg(feature = "deterministic")]
	mod deterministic {
		use std::collections::hash_map::DefaultHasher;
		use std::hash::{Hash, Hasher};

		use super::*;

		#[test]
		fn encrypt_deterministic() {
			let ctx = mk_ctx(|b| {
				b.set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
			});

			let encoder = BFVEncoder::new(&ctx).unwrap();

			let mut data = vec![];

			for i in 0..encoder.get_slot_count() {
				data.push(i as u64);
			}

			let plaintext = encoder.encode_u64(&data).unwrap();

			let public_key_bytes = include_bytes!("../tests/data/public_key.bin");
			let secret_key_bytes = include_bytes!("../tests/data/secret_key.bin");

			let public_key = PublicKey::from_bytes(&ctx, public_key_bytes).unwrap();
			let secret_key = SecretKey::from_bytes(&ctx, secret_key_bytes).unwrap();

			let encryptor =
				Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();
			let decryptor = Decryptor::new(&ctx, &secret_key).unwrap();

			let ciphertext = encryptor
				.encrypt_deterministic(&plaintext, &[0, 0, 0, 0, 0, 0, 0, 0])
				.unwrap();
			let decrypted = decryptor.decrypt(&ciphertext).unwrap();

			let data_2 = encoder.decode_u64(&decrypted).unwrap();

			assert_eq!(data, data_2);

			let cipher_bytes = ciphertext.as_bytes().unwrap();

			let mut s = DefaultHasher::new();
			cipher_bytes.hash(&mut s);
			let hash = s.finish();

			assert_eq!(
				hash,
				if cfg!(target_os = "macos") {
					14319785560025809101
				} else {
					9942548233613012008
				}
			);
		}
	}
}
