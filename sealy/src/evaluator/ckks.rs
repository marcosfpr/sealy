use std::ptr::null_mut;

use crate::evaluator::base::EvaluatorBase;
use crate::{
	bindgen, error::convert_seal_error, Ciphertext, Context, Evaluator, GaloisKey, Plaintext,
	RelinearizationKey, Result,
};

/// An evaluator that contains additional operations specific to the CKKS scheme.
pub struct CKKSEvaluator(EvaluatorBase);

impl std::ops::Deref for CKKSEvaluator {
	type Target = EvaluatorBase;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl CKKSEvaluator {
	/// Creates a CKKSEvaluator instance initialized with the specified Context.
	///  * `ctx` - The context.
	pub fn new(ctx: &Context) -> Result<CKKSEvaluator> {
		Ok(CKKSEvaluator(EvaluatorBase::new(ctx)?))
	}
}

impl Evaluator for CKKSEvaluator {
	type Plaintext = Plaintext;
	type Ciphertext = Ciphertext;

	fn negate_inplace(&self, a: &mut Ciphertext) -> Result<()> {
		self.0.negate_inplace(a)
	}

	fn negate(&self, a: &Ciphertext) -> Result<Ciphertext> {
		self.0.negate(a)
	}

	fn add_inplace(&self, a: &mut Ciphertext, b: &Ciphertext) -> Result<()> {
		self.0.add_inplace(a, b)
	}

	fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
		self.0.add(a, b)
	}

	fn add_many(&self, a: &[Ciphertext]) -> Result<Ciphertext> {
		self.0.add_many(a)
	}

	fn multiply_many(
		&self, a: &[Ciphertext], relin_keys: &RelinearizationKey,
	) -> Result<Ciphertext> {
		self.0.multiply_many(a, relin_keys)
	}

	fn sub_inplace(&self, a: &mut Ciphertext, b: &Ciphertext) -> Result<()> {
		self.0.sub_inplace(a, b)
	}

	fn sub(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
		self.0.sub(a, b)
	}

	fn multiply_inplace(&self, a: &mut Ciphertext, b: &Ciphertext) -> Result<()> {
		self.0.multiply_inplace(a, b)
	}

	fn multiply(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
		self.0.multiply(a, b)
	}

	fn square_inplace(&self, a: &mut Ciphertext) -> Result<()> {
		self.0.square_inplace(a)
	}

	fn square(&self, a: &Ciphertext) -> Result<Ciphertext> {
		self.0.square(a)
	}

	fn mod_switch_to_next(&self, a: &Ciphertext) -> Result<Ciphertext> {
		self.0.mod_switch_to_next(a)
	}

	fn mod_switch_to_next_inplace(&self, a: &Ciphertext) -> Result<()> {
		self.0.mod_switch_to_next_inplace(a)
	}

	fn mod_switch_to_next_plaintext(&self, a: &Plaintext) -> Result<Plaintext> {
		self.0.mod_switch_to_next_plaintext(a)
	}

	fn mod_switch_to_next_inplace_plaintext(&self, a: &Plaintext) -> Result<()> {
		self.0.mod_switch_to_next_inplace_plaintext(a)
	}

	fn exponentiate(
		&self, a: &Ciphertext, exponent: u64, relin_keys: &RelinearizationKey,
	) -> Result<Ciphertext> {
		self.0.exponentiate(a, exponent, relin_keys)
	}

	fn exponentiate_inplace(
		&self, a: &Ciphertext, exponent: u64, relin_keys: &RelinearizationKey,
	) -> Result<()> {
		self.0.exponentiate_inplace(a, exponent, relin_keys)
	}

	fn add_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
		self.0.add_plain(a, b)
	}

	fn add_plain_inplace(&self, a: &mut Ciphertext, b: &Plaintext) -> Result<()> {
		self.0.add_plain_inplace(a, b)
	}

	fn sub_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
		self.0.sub_plain(a, b)
	}

	fn sub_plain_inplace(&self, a: &mut Ciphertext, b: &Plaintext) -> Result<()> {
		self.0.sub_plain_inplace(a, b)
	}

	fn multiply_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
		self.0.multiply_plain(a, b)
	}

	fn multiply_plain_inplace(&self, a: &mut Ciphertext, b: &Plaintext) -> Result<()> {
		self.0.multiply_plain_inplace(a, b)
	}

	fn relinearize_inplace(
		&self, a: &mut Ciphertext, relin_keys: &RelinearizationKey,
	) -> Result<()> {
		convert_seal_error(unsafe {
			bindgen::Evaluator_Relinearize(
				self.get_handle(),
				a.get_handle(),
				relin_keys.get_handle(),
				a.get_handle(),
				null_mut(),
			)
		})?;

		Ok(())
	}

	fn relinearize(&self, a: &Ciphertext, relin_keys: &RelinearizationKey) -> Result<Ciphertext> {
		let out = Ciphertext::new()?;

		convert_seal_error(unsafe {
			bindgen::Evaluator_Relinearize(
				self.get_handle(),
				a.get_handle(),
				relin_keys.get_handle(),
				out.get_handle(),
				null_mut(),
			)
		})?;

		Ok(out)
	}

	fn rotate_rows(
		&self, a: &Ciphertext, steps: i32, galois_keys: &GaloisKey,
	) -> Result<Ciphertext> {
		let out = Ciphertext::new()?;

		convert_seal_error(unsafe {
			bindgen::Evaluator_RotateRows(
				self.get_handle(),
				a.get_handle(),
				steps,
				galois_keys.get_handle(),
				out.get_handle(),
				null_mut(),
			)
		})?;

		Ok(out)
	}

	fn rotate_rows_inplace(
		&self, a: &Ciphertext, steps: i32, galois_keys: &GaloisKey,
	) -> Result<()> {
		convert_seal_error(unsafe {
			bindgen::Evaluator_RotateRows(
				self.get_handle(),
				a.get_handle(),
				steps,
				galois_keys.get_handle(),
				a.get_handle(),
				null_mut(),
			)
		})?;

		Ok(())
	}

	fn rotate_columns(&self, a: &Ciphertext, galois_keys: &GaloisKey) -> Result<Ciphertext> {
		let out = Ciphertext::new()?;

		convert_seal_error(unsafe {
			bindgen::Evaluator_RotateColumns(
				self.get_handle(),
				a.get_handle(),
				galois_keys.get_handle(),
				out.get_handle(),
				null_mut(),
			)
		})?;

		Ok(out)
	}

	fn rotate_columns_inplace(&self, a: &Ciphertext, galois_keys: &GaloisKey) -> Result<()> {
		convert_seal_error(unsafe {
			bindgen::Evaluator_RotateColumns(
				self.get_handle(),
				a.get_handle(),
				galois_keys.get_handle(),
				a.get_handle(),
				null_mut(),
			)
		})?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {}
