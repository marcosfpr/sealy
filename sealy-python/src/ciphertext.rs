use pyo3::prelude::*;
use sealy::{FromBytes, ToBytes};

use crate::context::PyContext;
/// Class to store a ciphertext element.
#[derive(Debug, Clone)]
#[pyclass(module = "sealy", name = "Ciphertext")]
pub struct PyCiphertext {
	pub(crate) inner: sealy::Ciphertext,
}

#[pymethods]
impl PyCiphertext {
	/// Creates a new empty plaintext. Use an encoder to populate with a value.
	#[new]
	pub fn new() -> PyResult<Self> {
		let ciphertext = sealy::Ciphertext::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create ciphertext: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: ciphertext,
		})
	}

	/// Creates a new ciphertext from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		bytes: Vec<u8>,
	) -> PyResult<Self> {
		let ciphertext = sealy::Ciphertext::from_bytes(&context.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create ciphertext from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: ciphertext,
		})
	}

	/// Returns the ciphertext as a byte array.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		let data = self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get ciphertext as bytes: {:?}",
				e
			))
		})?;
		Ok(data)
	}

	/// Returns the number of polynomials in this ciphertext.
	pub fn get_num_polynomials(&self) -> u64 {
		self.inner.num_polynomials()
	}

	/// Returns the number of components in the coefficient modulus.
	pub fn get_coeff_modulus_size(&self) -> u64 {
		self.inner.coeff_modulus_size()
	}

	/// Returns the coefficient in the form the ciphertext is currently in (NTT
	/// form or not). For BFV, this will be the coefficient in the residual
	/// number system (RNS) format.
	pub fn get_coefficient(
		&self,
		poly_index: usize,
		coeff_index: usize,
	) -> PyResult<Vec<u64>> {
		let data = self
			.inner
			.get_coefficient(poly_index, coeff_index)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to get coefficient: {:?}",
					e
				))
			})?;
		Ok(data)
	}

	/// Returns whether the ciphertext is in NTT form.
	pub fn is_ntt_form(&self) -> bool {
		self.inner.is_ntt_form()
	}

	fn __eq__(
		&self,
		other: &PyCiphertext,
	) -> bool {
		self.inner == other.inner
	}
}
