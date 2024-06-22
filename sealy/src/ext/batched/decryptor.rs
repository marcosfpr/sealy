use super::Batch;
use crate::{Ciphertext, Context, Decryptor, Plaintext, Result, SecretKey};

/// Decrypts batches of ciphertexts.
pub struct BatchDecryptor {
	decryptor: Decryptor,
}

impl BatchDecryptor {
	/// Creates a new batch decryptor.
	pub fn new(ctx: &Context, secret_key: &SecretKey) -> Result<Self> {
		Ok(Self {
			decryptor: Decryptor::new(ctx, secret_key)?,
		})
	}
}

impl BatchDecryptor {
	/// Decrypts a ciphertext and returns the plaintext.
	///
	/// * `ciphertext` - The ciphertext to decrypt.
	pub fn decrypt(&self, ciphertext_batch: &Batch<Ciphertext>) -> Result<Batch<Plaintext>> {
		ciphertext_batch
			.map(|ciphertext| self.decryptor.decrypt(ciphertext))
			.collect()
	}
}
