use pyo3::prelude::*;

/// Memory pool handle for SEAL.
#[derive(Debug)]
#[pyclass(module = "sealy", name = "MemoryPool")]
pub struct PyMemoryPool {
	pub(crate) inner: sealy::MemoryPool,
}

#[pymethods]
impl PyMemoryPool {
	/// Creates an instance of MemoryPool.
	#[new]
	pub fn new() -> PyResult<Self> {
		let memory_pool = sealy::MemoryPool::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create memory pool: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: memory_pool,
		})
	}
}
