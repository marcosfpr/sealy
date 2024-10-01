use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::component_marker;
use crate::error::*;
use crate::poly_array::PolynomialArray;
use crate::try_seal;
use crate::{
	Asym, AsymmetricComponents, Ciphertext, Context, Plaintext, PublicKey, SecretKey, Sym, SymAsym,
	SymmetricComponents,
};

/// Encrypts Plaintext objects into Ciphertext objects.
///
/// Constructing an Encryptor requires a SEALContext with valid encryption parameters, the public
/// key and/or the secret key. If an Encrytor is given a secret key, it supports symmetric-key
/// encryption. If an Encryptor is given a public key, it supports asymmetric-key encryption.
///
/// Overloads
/// For the encrypt function we provide two overloads concerning the memory pool used in
/// allocations needed during the operation. In one overload the global memory pool is used
/// for this purpose, and in another overload the user can supply a MemoryPoolHandle
/// to to be used instead. This is to allow one single Encryptor to be used concurrently by
/// several threads without running into thread contention in allocations taking place during
/// operations. For example, one can share one single Encryptor across any number of threads,
/// but in each thread call the encrypt function by giving it a thread-local MemoryPoolHandle
/// to use. It is important for a developer to understand how this works to avoid unnecessary
/// performance bottlenecks.
///
/// NTT form
/// When using the BFV scheme (SchemeType.BFV), all plaintext and ciphertexts should
/// remain by default in the usual coefficient representation, i.e. not in NTT form.
/// When using the CKKS scheme (SchemeType.CKKS), all plaintexts and ciphertexts
/// should remain by default in NTT form. We call these scheme-specific NTT states the
/// "default NTT form". Decryption requires the input ciphertexts to be in the default
/// NTT form, and will throw an exception if this is not the case.
pub struct Encryptor<T = ()> {
	handle: AtomicPtr<c_void>,
	_marker: PhantomData<T>,
}

/// An encryptor capable of symmetric encryptions.
pub type SymmetricEncryptor = Encryptor<Sym>;

/// An encryptor capable of asymmetric encryptions.
pub type AsymmetricEncryptor = Encryptor<Asym>;

/// An encryptor capable of both symmetric and asymmetric encryptions.
pub type SymAsymEncryptor = Encryptor<SymAsym>;

impl<T> Encryptor<T> {
	/// Returns the underlying pointer to the SEAL object.
	pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
		self.handle.load(Ordering::SeqCst)
	}
}

impl Encryptor {
	/// Creates an Encryptor instance initialized with the specified SEALContext,
	/// public key, and secret key.
	///
	/// * `ctx` - The SEALContext
	/// * `publicKey` - The public key
	/// * `secretKey` - The secret key
	pub fn with_public_and_secret_key(
		ctx: &Context,
		public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<Encryptor<SymAsym>> {
		let mut handle: *mut c_void = null_mut();

		try_seal!(unsafe {
			bindgen::Encryptor_Create(
				ctx.get_handle(),
				public_key.get_handle(),
				secret_key.get_handle(),
				&mut handle,
			)
		})?;

		Ok(Encryptor {
			handle: AtomicPtr::new(handle),
			_marker: PhantomData,
		})
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext,
	/// public key.
	pub fn with_public_key(
		ctx: &Context,
		public_key: &PublicKey,
	) -> Result<AsymmetricEncryptor> {
		let mut handle: *mut c_void = null_mut();

		try_seal!(unsafe {
			bindgen::Encryptor_Create(
				ctx.get_handle(),
				public_key.get_handle(),
				null_mut(),
				&mut handle,
			)
		})?;

		Ok(Encryptor {
			handle: AtomicPtr::new(handle),
			_marker: PhantomData,
		})
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext and
	/// secret key.
	pub fn with_secret_key(
		ctx: &Context,
		secret_key: &SecretKey,
	) -> Result<SymmetricEncryptor> {
		let mut handle: *mut c_void = null_mut();

		try_seal!(unsafe {
			bindgen::Encryptor_Create(
				ctx.get_handle(),
				null_mut(),
				secret_key.get_handle(),
				&mut handle,
			)
		})?;

		Ok(Encryptor {
			handle: AtomicPtr::new(handle),
			_marker: PhantomData,
		})
	}
}

impl AsymmetricEncryptor {
	/// Create a new asymmetric encryptor.
	pub fn new(
		ctx: &Context,
		public_key: &PublicKey,
	) -> Result<Self> {
		Encryptor::with_public_key(ctx, public_key)
	}
}

impl SymmetricEncryptor {
	/// Create a new symmetric encryptor.
	pub fn new(
		ctx: &Context,
		secret_key: &SecretKey,
	) -> Result<Self> {
		Encryptor::with_secret_key(ctx, secret_key)
	}
}

impl SymAsymEncryptor {
	/// Create a new encryptor capable of both symmetric and asymmetric encryption.
	pub fn new(
		ctx: &Context,
		public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<Self> {
		Encryptor::with_public_and_secret_key(ctx, public_key, secret_key)
	}
}

impl<T: component_marker::Asym> Encryptor<T> {
	/// Encrypts a plaintext with the public key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	pub fn encrypt(
		&self,
		plaintext: &Plaintext,
	) -> Result<Ciphertext> {
		// We don't call the encrypt_return_components because the return
		// components are allocated on the SEAL global memory pool. By calling
		// the regular encrypt function, we skip that allocation.
		let ciphertext = Ciphertext::new()?;

		try_seal!(unsafe {
			bindgen::Encryptor_Encrypt(
				self.get_handle(),
				plaintext.get_handle(),
				ciphertext.get_handle(),
				null_mut(),
			)
		})?;

		Ok(ciphertext)
	}

	/// Encrypts a plaintext with the public key and returns the ciphertext as a
	/// serializable object. Also returns the u and e values used in encrypting
	/// the value.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	pub fn encrypt_return_components(
		&self,
		plaintext: &Plaintext,
	) -> Result<(Ciphertext, AsymmetricComponents)> {
		let ciphertext = Ciphertext::new()?;
		let u_destination = PolynomialArray::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		try_seal!(unsafe {
			bindgen::Encryptor_EncryptReturnComponents(
				self.get_handle(),
				plaintext.get_handle(),
				true,
				ciphertext.get_handle(),
				u_destination.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				null_mut(),
			)
		})?;

		Ok((
			ciphertext,
			AsymmetricComponents::new(u_destination, e_destination, r_destination),
		))
	}

	/// DO NOT USE THIS FUNCTION IN PRODUCTION: IT PRODUCES DETERMINISTIC
	/// ENCRYPTIONS. IT IS INHERENTLY INSECURE, AND ONLY MEANT FOR TESTING OR
	/// DEMONSTRATION PURPOSES.
	///
	/// Encrypts a plaintext with the public key and returns the ciphertext as a
	/// serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	/// * `seed` - The seed to use for encryption.
	#[cfg(feature = "deterministic")]
	pub fn encrypt_deterministic(
		&self,
		plaintext: &Plaintext,
		seed: &[u64; 8],
	) -> Result<Ciphertext> {
		let ciphertext = Ciphertext::new()?;
		let u_destination = PolynomialArray::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		// We do not need the components so we do not export them.
		try_seal!(unsafe {
			bindgen::Encryptor_EncryptReturnComponentsSetSeed(
				self.get_handle(),
				plaintext.get_handle(),
				false,
				ciphertext.get_handle(),
				u_destination.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				seed.as_ptr() as *mut c_void,
				null_mut(),
			)
		})?;

		Ok(ciphertext)
	}

	/// DO NOT USE THIS FUNCTION IN PRODUCTION: IT PRODUCES DETERMINISTIC
	/// ENCRYPTIONS. IT IS INHERENTLY INSECURE, AND ONLY MEANT FOR TESTING OR
	/// DEMONSTRATION PURPOSES.
	///
	/// Encrypts a plaintext with the public key and returns the ciphertext as a
	/// serializable object. Also returns the u and e values used in encrypting
	/// the value.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	/// * `seed` - The seed to use for encryption.
	#[cfg(feature = "deterministic")]
	pub fn encrypt_return_components_deterministic(
		&self,
		plaintext: &Plaintext,
		seed: &[u64; 8],
	) -> Result<(Ciphertext, AsymmetricComponents)> {
		let ciphertext = Ciphertext::new()?;
		let u_destination = PolynomialArray::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		// We do not need the components so we do not export them.
		try_seal!(unsafe {
			bindgen::Encryptor_EncryptReturnComponentsSetSeed(
				self.get_handle(),
				plaintext.get_handle(),
				true,
				ciphertext.get_handle(),
				u_destination.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				seed.as_ptr() as *mut c_void,
				null_mut(),
			)
		})?;

		Ok((
			ciphertext,
			AsymmetricComponents::new(u_destination, e_destination, r_destination),
		))
	}
}

impl<T: component_marker::Sym> Encryptor<T> {
	/// Encrypts a plaintext with the secret key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	pub fn encrypt_symmetric(
		&self,
		plaintext: &Plaintext,
	) -> Result<Ciphertext> {
		// We don't call the encrypt_return_components because the return
		// components are allocated on the SEAL global memory pool. By calling
		// the regular encrypt function, we skip that allocation.
		let ciphertext = Ciphertext::new()?;

		try_seal!(unsafe {
			bindgen::Encryptor_EncryptSymmetric(
				self.get_handle(),
				plaintext.get_handle(),
				false,
				ciphertext.get_handle(),
				null_mut(),
			)
		})?;

		Ok(ciphertext)
	}

	/// DO NOT USE THIS FUNCTION IN PRODUCTION: IT PRODUCES DETERMINISTIC
	/// ENCRYPTIONS. IT IS INHERENTLY INSECURE, AND ONLY MEANT FOR TESTING OR
	/// DEMONSTRATION PURPOSES.
	///
	/// Encrypts a plaintext with the secret key and returns the ciphertext as a
	/// serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	/// * `seed` - The seed to use for encryption.
	#[cfg(feature = "deterministic")]
	pub fn encrypt_symmetric_deterministic(
		&self,
		plaintext: &Plaintext,
		seed: &[u64; 8],
	) -> Result<Ciphertext> {
		let ciphertext = Ciphertext::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		// We do not need the components so we do not export them.
		try_seal!(unsafe {
			bindgen::Encryptor_EncryptSymmetricReturnComponentsSetSeed(
				self.get_handle(),
				plaintext.get_handle(),
				ciphertext.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				seed.as_ptr() as *mut c_void,
				null_mut(),
			)
		})?;

		Ok(ciphertext)
	}

	/// Encrypts a plaintext with the secret key and returns the ciphertext as a
	/// serializable object. Also returns the e (noise) and r (remainder) values used in
	/// encrypting the value.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	pub fn encrypt_symmetric_return_components(
		&self,
		plaintext: &Plaintext,
	) -> Result<(Ciphertext, SymmetricComponents)> {
		let ciphertext = Ciphertext::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		try_seal!(unsafe {
			bindgen::Encryptor_EncryptSymmetricReturnComponents(
				self.get_handle(),
				plaintext.get_handle(),
				ciphertext.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				null_mut(),
			)
		})?;

		Ok((
			ciphertext,
			SymmetricComponents::new(e_destination, r_destination),
		))
	}

	/// DO NOT USE THIS FUNCTION IN PRODUCTION: IT PRODUCES DETERMINISTIC
	/// ENCRYPTIONS. IT IS INHERENTLY INSECURE, AND ONLY MEANT FOR TESTING OR
	/// DEMONSTRATION PURPOSES.
	///
	/// Encrypts a plaintext with the public key and returns the ciphertext as a
	/// serializable object. Also returns the u and e values used in encrypting
	/// the value.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plainext` - The plaintext to encrypt.
	/// * `seed` - The seed to use for encryption.
	#[cfg(feature = "deterministic")]
	pub fn encrypt_symmetric_return_components_deterministic(
		&self,
		plaintext: &Plaintext,
		seed: &[u64; 8],
	) -> Result<(Ciphertext, SymmetricComponents)> {
		let ciphertext = Ciphertext::new()?;
		let e_destination = PolynomialArray::new()?;
		let r_destination = Plaintext::new()?;

		// We do not need the components so we do not export them.
		try_seal!(unsafe {
			bindgen::Encryptor_EncryptSymmetricReturnComponentsSetSeed(
				self.get_handle(),
				plaintext.get_handle(),
				ciphertext.get_handle(),
				e_destination.get_handle(),
				r_destination.get_handle(),
				seed.as_ptr() as *mut c_void,
				null_mut(),
			)
		})?;

		Ok((
			ciphertext,
			SymmetricComponents::new(e_destination, r_destination),
		))
	}
}

impl<T> Drop for Encryptor<T> {
	fn drop(&mut self) {
		try_seal!(unsafe { bindgen::Encryptor_Destroy(self.get_handle()) })
			.expect("Internal error in Enryptor::drop");
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

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
	fn can_create_encryptor_from_public_key() {
		let ctx = mk_ctx(|b| b);
		let gen = KeyGenerator::new(&ctx).unwrap();

		let public_key = gen.create_public_key();

		let encryptor = Encryptor::with_public_key(&ctx, &public_key).unwrap();

		std::mem::drop(encryptor);
	}

	#[test]
	fn can_create_encryptor_from_secret_key() {
		let ctx = mk_ctx(|b| b);

		let gen = KeyGenerator::new(&ctx).unwrap();

		let secret_key = gen.secret_key();

		let encryptor = Encryptor::with_secret_key(&ctx, &secret_key).unwrap();

		std::mem::drop(encryptor);
	}

	#[test]
	fn can_create_encryptor_from_public_and_secret_key() {
		let ctx = mk_ctx(|b| b);

		let gen = KeyGenerator::new(&ctx).unwrap();

		let public_key = gen.create_public_key();
		let secret_key = gen.secret_key();

		let encryptor =
			Encryptor::with_public_and_secret_key(&ctx, &public_key, &secret_key).unwrap();

		std::mem::drop(encryptor);
	}
}
