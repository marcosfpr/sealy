use crate::{
	component_marker, Asym, AsymmetricComponents, Ciphertext, Context, Encryptor, Plaintext,
	PublicKey, Result, SecretKey, Sym, SymAsym, SymmetricComponents,
};

use super::Tensor;

/// Encryptor that can encrypt multiple messages at once.
pub struct TensorEncryptor<T = ()> {
	encryptor: Encryptor<T>,
	typ: std::marker::PhantomData<T>,
}

impl<T> TensorEncryptor<T> {
	/// Creates a new tensorEncryptor instance.
	pub fn new(encryptor: Encryptor<T>) -> Self {
		Self {
			encryptor,
			typ: std::marker::PhantomData,
		}
	}
}

impl TensorEncryptor {
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
	) -> Result<TensorEncryptor<SymAsym>> {
		Ok(TensorEncryptor::new(Encryptor::with_public_and_secret_key(
			ctx, public_key, secret_key,
		)?))
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext,
	/// public key.
	pub fn with_public_key(
		ctx: &Context,
		public_key: &PublicKey,
	) -> Result<TensorEncryptor<Asym>> {
		Ok(TensorEncryptor::new(Encryptor::with_public_key(
			ctx, public_key,
		)?))
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext and
	/// secret key.
	pub fn with_secret_key(
		ctx: &Context,
		secret_key: &SecretKey,
	) -> Result<TensorEncryptor<Sym>> {
		Ok(TensorEncryptor::new(Encryptor::with_secret_key(
			ctx, secret_key,
		)?))
	}
}

impl<T: component_marker::Asym> TensorEncryptor<T> {
	/// Encrypts a plaintext with the public key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_tensor` - The plaintext to encrypt.
	pub fn encrypt(
		&self,
		plaintext_tensor: &Tensor<Plaintext>,
	) -> Result<Tensor<Ciphertext>> {
		plaintext_tensor
			.map(|plaintext| self.encryptor.encrypt(plaintext))
			.collect()
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
	/// * `plaintext_tensor` - The plaintext to encrypt.
	pub fn encrypt_return_components(
		&self,
		plaintext_tensor: &Tensor<Plaintext>,
	) -> Result<Tensor<(Ciphertext, AsymmetricComponents)>> {
		plaintext_tensor
			.map(|plaintext| self.encryptor.encrypt_return_components(plaintext))
			.collect()
	}
}

impl<T: component_marker::Sym> TensorEncryptor<T> {
	/// Encrypts a plaintext with the secret key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    Dynamic memory allocations in the process are allocated from the memory
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_tensor` - The plaintext to encrypt.
	pub fn encrypt_symmetric(
		&self,
		plaintext_tensor: &Tensor<Plaintext>,
	) -> Result<Tensor<Ciphertext>> {
		plaintext_tensor
			.map(|plaintext| self.encryptor.encrypt_symmetric(plaintext))
			.collect()
	}

	/// Encrypts a plaintext with the secret key and returns the ciphertext as a
	/// serializable object. Also returns the e (noise) and r (remainder) values used in
	/// encrypting the value.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	///    pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_tensor` - The plaintext to encrypt.
	pub fn encrypt_symmetric_return_components(
		&self,
		plaintext_tensor: &Tensor<Plaintext>,
	) -> Result<Tensor<(Ciphertext, SymmetricComponents)>> {
		plaintext_tensor
			.map(|plaintext| {
				self.encryptor
					.encrypt_symmetric_return_components(plaintext)
			})
			.collect()
	}
}
