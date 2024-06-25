use pyo3::prelude::*;

use crate::{context_data::PyContextData, PyEncryptionParameters, PySecurityLevel};

/// Performs sanity checks (validation) and pre-computations for a given set of encryption
/// parameters. While the EncryptionParameters class is intended to be a light-weight class
/// to store the encryption parameters, the SEALContext class is a heavy-weight class that
/// is constructed from a given set of encryption parameters. It validates the parameters
/// for correctness, evaluates their properties, and performs and stores the results of
/// several costly pre-computations.
#[pyclass(name = "Context")]
pub struct PyContext {
	pub(crate) inner: sealy::Context,
}

#[pymethods]
impl PyContext {
	/// Creates an instance of SEALContext and performs several pre-computations
	/// on the given EncryptionParameters.
	#[new]
	pub fn new(
		params: &PyEncryptionParameters, expand_mod_chain: bool, security_level: PySecurityLevel,
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

	/// Returns the ContextData given a parms_id.
	pub fn get_context_data(&self, parms_id: Vec<u64>) -> PyResult<PyContextData> {
		let context_data = self.inner.get_context_data(&parms_id).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get context data: {:?}",
				e
			))
		})?;
		Ok(PyContextData {
			inner: context_data,
		})
	}

	/// Returns the first ContextData in the modulus switching chain.
	pub fn get_first_context_data(&self) -> PyResult<PyContextData> {
		let context_data = self.inner.get_first_context_data().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get first context data: {:?}",
				e
			))
		})?;
		Ok(PyContextData {
			inner: context_data,
		})
	}

	/// Returns the last ContextData in the modulus switching chain.
	pub fn get_last_context_data(&self) -> PyResult<PyContextData> {
		let last_context_data = self.inner.get_last_context_data().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get last context data: {:?}",
				e
			))
		})?;
		Ok(PyContextData {
			inner: last_context_data,
		})
	}
}
