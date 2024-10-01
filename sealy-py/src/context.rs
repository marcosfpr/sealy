use pyo3::prelude::*;

use crate::{PyEncryptionParameters, PySecurityLevel};

/// Performs sanity checks (validation) and pre-computations for a given set of encryption
/// parameters. While the EncryptionParameters class is intended to be a light-weight class
/// to store the encryption parameters, the sealy::Context class is a heavy-weight class that
/// is constructed from a given set of encryption parameters. It validates the parameters
/// for correctness, evaluates their properties, and performs and stores the results of
/// several costly pre-computations.
#[pyclass(module = "sealy", name = "Context")]
pub struct PyContext {
	pub(crate) inner: sealy::Context,
}

#[pymethods]
impl PyContext {
	/// Creates an instance of sealy::Context and performs several pre-computations
	/// on the given EncryptionParameters.
	#[new]
	pub fn new(
		params: &PyEncryptionParameters,
		expand_mod_chain: bool,
		security_level: PySecurityLevel,
	) -> PyResult<Self> {
		let context = sealy::Context::new(&params.inner, expand_mod_chain, security_level.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to create context: {:?}",
					e
				))
			})?;

		Ok(Self {
			inner: context,
		})
	}

	/// Returns the key ContextData in the modulus switching chain.
	pub fn get_key_parms_id(&self) -> PyResult<Vec<u64>> {
		let parms_id = self.inner.get_key_parms_id().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get key parms id: {:?}",
				e
			))
		})?;
		Ok(parms_id)
	}

	/// Returns the last ContextData in the modulus switching chain.
	pub fn get_last_parms_id(&self) -> PyResult<Vec<u64>> {
		let last_parms_id = self.inner.get_last_parms_id().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get last parms id: {:?}",
				e
			))
		})?;
		Ok(last_parms_id)
	}

	/// Returns the first ContextData in the modulus switching chain.
	pub fn get_first_parms_id(&self) -> PyResult<Vec<u64>> {
		let first_parms_id = self.inner.get_first_parms_id().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get first parms id: {:?}",
				e
			))
		})?;
		Ok(first_parms_id)
	}

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

	/// Returns the security level of the encryption parameters.
	pub fn get_security_level(&self) -> PyResult<PySecurityLevel> {
		let security_level = self.inner.get_security_level().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get security level: {:?}",
				e
			))
		})?;

		Ok(PySecurityLevel {
			inner: security_level,
		})
	}

	pub fn __getnewargs__(&self) -> PyResult<(PyEncryptionParameters, bool, PySecurityLevel)> {
		let expand_mod_chain = true;
		let params = self.get_encryption_parameters()?;
		let security_level = self.get_security_level()?;

		Ok((params, expand_mod_chain, security_level))
	}
}
