use pyo3::prelude::*;
use sealy::ContextData;

use crate::parameters::PyEncryptionParameters;

///  ContextData holds context pre-computation data for a given set of encryption parameters.
#[derive(Debug)]
#[pyclass(name = "ContextData")]
pub struct PyContextData {
	pub(crate) inner: ContextData,
}

#[pymethods]
impl PyContextData {
	/// Returns the encryption parameters used to create the context data.
	pub fn get_encryption_parameters(&self) -> PyResult<PyEncryptionParameters> {
		let encryption_parameters = self.inner.get_encryption_parameters().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get encryption parameters: {:?}",
				e
			))
		})?;
		Ok(PyEncryptionParameters {
			inner: encryption_parameters,
		})
	}

	/// Returns the total number of primes in the coefficient modulus.
	pub fn get_total_coeff_modulus_bit_count(&self) -> PyResult<i32> {
		let bit_count = self
			.inner
			.get_total_coeff_modulus_bit_count()
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to get total coefficient modulus bit count: {:?}",
					e
				))
			})?;
		Ok(bit_count)
	}
}
