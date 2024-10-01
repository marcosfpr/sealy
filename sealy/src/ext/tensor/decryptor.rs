use super::Tensor;
use crate::{Ciphertext, Context, Decryptor, Plaintext, Result, SecretKey};

/// Decrypts batches of ciphertexts.
pub struct TensorDecryptor {
	decryptor: Decryptor,
}

impl TensorDecryptor {
	/// Creates a new batch decryptor.
	pub fn new(
		ctx: &Context,
		secret_key: &SecretKey,
	) -> Result<Self> {
		Ok(Self {
			decryptor: Decryptor::new(ctx, secret_key)?,
		})
	}
}

impl TensorDecryptor {
	/// Decrypts a ciphertext and returns the plaintext.
	///
	/// * `ciphertext` - The ciphertext to decrypt.
	pub fn decrypt(
		&self,
		ciphertext_batch: &Tensor<Ciphertext>,
	) -> Result<Tensor<Plaintext>> {
		ciphertext_batch
			.map(|ciphertext| self.decryptor.decrypt(ciphertext))
			.collect()
	}
}
