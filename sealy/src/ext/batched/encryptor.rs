use crate::{
	enc_marker, Asym, AsymmetricComponents, Ciphertext, Context, Encryptor, Plaintext, PublicKey,
	Result, SecretKey, Sym, SymAsym, SymmetricComponents,
};

use super::Batch;

/// Encryptor that can encrypt multiple messages at once.
pub struct BatchEncryptor<T = ()> {
	encryptor: Encryptor<T>,
	typ: std::marker::PhantomData<T>,
}

impl<T> BatchEncryptor<T> {
	/// Creates a new BatchEncryptor instance.
	pub fn new(encryptor: Encryptor<T>) -> Self {
		Self {
			encryptor,
			typ: std::marker::PhantomData,
		}
	}
}

impl BatchEncryptor {
	/// Creates an Encryptor instance initialized with the specified SEALContext,
	/// public key, and secret key.
	///
	/// * `ctx` - The SEALContext
	/// * `publicKey` - The public key
	/// * `secretKey` - The secret key
	pub fn with_public_and_secret_key(
		ctx: &Context, public_key: &PublicKey, secret_key: &SecretKey,
	) -> Result<BatchEncryptor<SymAsym>> {
		Ok(BatchEncryptor::new(Encryptor::with_public_and_secret_key(
			ctx, public_key, secret_key,
		)?))
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext,
	/// public key.
	pub fn with_public_key(ctx: &Context, public_key: &PublicKey) -> Result<BatchEncryptor<Asym>> {
		Ok(BatchEncryptor::new(Encryptor::with_public_key(
			ctx, public_key,
		)?))
	}

	/// Creates an Encryptor instance initialized with the specified SEALContext and
	/// secret key.
	pub fn with_secret_key(ctx: &Context, secret_key: &SecretKey) -> Result<BatchEncryptor<Sym>> {
		Ok(BatchEncryptor::new(Encryptor::with_secret_key(
			ctx, secret_key,
		)?))
	}
}

impl<T: enc_marker::Asym> BatchEncryptor<T> {
	/// Encrypts a plaintext with the public key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	/// Dynamic memory allocations in the process are allocated from the memory
	/// pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_batch` - The plaintext to encrypt.
	pub fn encrypt(&self, plaintext_batch: &Batch<Plaintext>) -> Result<Batch<Ciphertext>> {
		plaintext_batch
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
	/// Dynamic memory allocations in the process are allocated from the memory
	/// pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_batch` - The plaintext to encrypt.
	pub fn encrypt_return_components(
		&self, plaintext_batch: &Batch<Plaintext>,
	) -> Result<Batch<(Ciphertext, AsymmetricComponents)>> {
		plaintext_batch
			.map(|plaintext| self.encryptor.encrypt_return_components(plaintext))
			.collect()
	}
}

impl<T: enc_marker::Sym> BatchEncryptor<T> {
	/// Encrypts a plaintext with the secret key and returns the ciphertext as
	/// a serializable object.
	///
	/// The encryption parameters for the resulting ciphertext correspond to:
	/// 1) in BFV, the highest (data) level in the modulus switching chain,
	/// 2) in CKKS, the encryption parameters of the plaintext.
	/// Dynamic memory allocations in the process are allocated from the memory
	/// pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_batch` - The plaintext to encrypt.
	pub fn encrypt_symmetric(
		&self, plaintext_batch: &Batch<Plaintext>,
	) -> Result<Batch<Ciphertext>> {
		plaintext_batch
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
	/// pool pointed to by the given MemoryPoolHandle.
	///
	/// * `plaintext_batch` - The plaintext to encrypt.
	pub fn encrypt_symmetric_return_components(
		&self, plaintext_batch: &Batch<Plaintext>,
	) -> Result<Batch<(Ciphertext, SymmetricComponents)>> {
		plaintext_batch
			.map(|plaintext| {
				self.encryptor
					.encrypt_symmetric_return_components(plaintext)
			})
			.collect()
	}
}
