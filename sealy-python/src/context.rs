use pyo3::{
	prelude::*,
	types::{PyBytes, PyType},
};

use crate::{
	context_data::PyContextData,
	parameters::{PyEncryptionParameters, PySecurityLevel},
};

/// Performs sanity checks (validation) and pre-computations for a given set of encryption
/// parameters. While the EncryptionParameters class is intended to be a light-weight class
/// to store the encryption parameters, the SEALContext class is a heavy-weight class that
/// is constructed from a given set of encryption parameters. It validates the parameters
/// for correctness, evaluates their properties, and performs and stores the results of
/// several costly pre-computations.
#[pyclass(module = "sealy", name = "Context")]
pub struct PyContext {
	pub(crate) inner: sealy::Context,
}

#[pymethods]
impl PyContext {
	/// Creates a new dangling context.
	#[new]
	pub fn new() -> PyResult<Self> {
		Ok(Self {
			inner: sealy::Context::new_dangling(),
		})
	}

	/// Creates an instance of SEALContext and performs several pre-computations
	/// on the given EncryptionParameters.
	#[classmethod]
	pub fn build(
		_cls: &Bound<'_, PyType>, params: &PyEncryptionParameters, expand_mod_chain: bool,
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

	/// Returns the key ContextData in the modulus switching chain.
	pub fn __deepcopy__(&self, _memo: Py<PyAny>) -> PyResult<Self> {
		let params = self.inner.get_params().cloned().ok_or(PyErr::new::<
			pyo3::exceptions::PyRuntimeError,
			_,
		>(
			"Failed to get parameters".to_string(),
		))?;

		let enc_params = sealy::EncryptionParameters::new(params.scheme_type()).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Error creating parameters: {}",
				e
			))
		})?;

		let inner = sealy::Context::new(
			&enc_params,
			params.expand_mod_chain(),
			params.security_level(),
		)
		.map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create context: {:?}",
				e
			))
		})?;

		Ok(Self {
			inner,
		})
	}

	/// Returns the parameters used to create the context.
	pub fn __getstate__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
		let params = self.inner.get_params().cloned().ok_or(PyErr::new::<
			pyo3::exceptions::PyRuntimeError,
			_,
		>(
			"Failed to get parameters".to_string(),
		))?;

		// serde serialize to string
		let serialized = serde_json::to_string(&params).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to serialize context: {:?}",
				e
			))
		})?;

		let bytes = PyBytes::new_bound(py, serialized.as_bytes());

		Ok(bytes)
	}

	/// Reconstructs the context from the serialized state.
	pub fn __setstate__(&mut self, state: Bound<'_, PyBytes>) -> PyResult<()> {
		println!("setting state from {:?}", state);

		let state = state.as_bytes();

		// reconstruct the parameters from the serialized state
		let params: sealy::ContextParams = serde_json::from_slice(state).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to deserialize context params: {:?}",
				e
			))
		})?;

		let enc_params = sealy::EncryptionParameters::new(params.scheme_type()).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Error creating parameters: {}",
				e
			))
		})?;

		let inner = sealy::Context::new(
			&enc_params,
			params.expand_mod_chain(),
			params.security_level(),
		)
		.map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create context: {:?}",
				e
			))
		})?;

		self.inner = inner;

		println!("set state to {:?}", self.inner.get_params());

		Ok(())
	}
}
