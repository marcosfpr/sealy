use pyo3::prelude::*;

use crate::{
	ciphertext::PyCiphertext, context::PyContext, keys::PySecretKey, plaintext::PyPlaintext,
};

/// Decrypts Ciphertext objects into Plaintext objects.
#[pyclass(module = "sealy", name = "Decryptor")]
pub struct PyDecryptor {
	inner: sealy::Decryptor,
}

#[pymethods]
impl PyDecryptor {
	/// Creates a Decryptor instance initialized with the specified sealy::Context
	/// and secret key.
	#[new]
	pub fn new(
		ctx: &PyContext,
		secret_key: &PySecretKey,
	) -> PyResult<Self> {
		let decryptor = sealy::Decryptor::new(&ctx.inner, &secret_key.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create Decryptor: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: decryptor,
		})
	}

	/// Decrypts a Ciphertext and stores the result in the destination parameter.
	///
	///  * `encrypted` - The ciphertext to decrypt.
	pub fn decrypt(
		&self,
		ciphertext: &PyCiphertext,
	) -> PyResult<PyPlaintext> {
		let decrypted = self.inner.decrypt(&ciphertext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decrypt ciphertext: {:?}",
				e
			))
		})?;
		Ok(PyPlaintext {
			inner: decrypted,
		})
	}

	/// Computes the invariant noise budget (in bits) of a ciphertext. The invariant noise
	/// budget measures the amount of room there is for the noise to grow while ensuring
	/// correct decryptions. Dynamic memory allocations in the process are allocated from
	/// the memory pool pointed to by the given MemoryPoolHandle. This function works only
	/// with the BFV scheme.
	pub fn invariant_noise_budget(
		&self,
		ciphertext: &PyCiphertext,
	) -> PyResult<u32> {
		let budget = self
			.inner
			.invariant_noise_budget(&ciphertext.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to compute invariant noise budget: {:?}",
					e
				))
			})?;
		Ok(budget)
	}

	/// Computes the invariant noise of a ciphertext. The invariant noise is
	/// a value that increases with FHE operations. This function only works
	/// with the BFV scheme.
	pub fn invariant_noise(
		&self,
		ciphertext: &PyCiphertext,
	) -> PyResult<f64> {
		let noise = self.inner.invariant_noise(&ciphertext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to compute invariant noise: {:?}",
				e
			))
		})?;
		Ok(noise)
	}
}
