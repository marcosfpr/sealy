use pyo3::prelude::*;

use crate::{context::PyContext, plaintext::PyPlaintext};

/// Provides functionality for CRT batching.
#[derive(Debug)]
#[pyclass(module = "sealy", name = "BFVEncoder")]
pub struct PyBFVEncoder {
	inner: sealy::BFVEncoder,
}

#[pymethods]
impl PyBFVEncoder {
	/// Creates a BatchEncoder.
	#[new]
	pub fn new(ctx: &PyContext) -> PyResult<Self> {
		let encoder = sealy::BFVEncoder::new(&ctx.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create BFVEncoder: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: encoder,
		})
	}

	/// Returns the number of "Batched" slots in this encoder produces.
	pub fn get_slot_count(&self) -> usize {
		self.inner.get_slot_count()
	}

	/// Encodes the given data into a plaintext.
	pub fn encode_int(
		&self,
		data: Vec<i64>,
	) -> PyResult<PyPlaintext> {
		let encoded = self.inner.encode_i64(&data).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encode data: {:?}",
				e
			))
		})?;
		Ok(PyPlaintext {
			inner: encoded,
		})
	}

	/// Decodes the given plaintext into data.
	pub fn decode_int(
		&self,
		plaintext: &PyPlaintext,
	) -> PyResult<Vec<i64>> {
		let encoded = self.inner.decode_i64(&plaintext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decode data: {:?}",
				e
			))
		})?;
		Ok(encoded)
	}

	/// Encodes the given data into a plaintext.
	pub fn encode_float(
		&self,
		data: Vec<f64>,
		base: f64,
	) -> PyResult<PyPlaintext> {
		let encoded = self.inner.encode_f64(&data, base).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encode data: {:?}",
				e
			))
		})?;
		Ok(PyPlaintext {
			inner: encoded,
		})
	}

	/// Decodes the given plaintext into data.
	pub fn decode_float(
		&self,
		plaintext: &PyPlaintext,
		base: f64,
	) -> PyResult<Vec<f64>> {
		let decoded = self.inner.decode_f64(&plaintext.inner, base).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decode data: {:?}",
				e
			))
		})?;
		Ok(decoded)
	}
}

/// To create CKKS plaintexts we need a special encoder: there is no other way
/// to create them. The BatchEncoder cannot be used with the
/// CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
/// Plaintext objects, which can subsequently be encrypted. At a high level this
/// looks a lot like what BatchEncoder does for the BFV scheme, but the theory
/// behind it is completely different.
#[derive(Debug)]
#[pyclass(module = "sealy", name = "CKKSEncoder")]
pub struct PyCKKSEncoder {
	pub(crate) inner: sealy::CKKSEncoder,
}

#[pymethods]
impl PyCKKSEncoder {
	/// Creates a CKKSEncoder. It is necessary that the encryption parameters
	/// given through the sealy::Context object support it.
	#[new]
	pub fn new(
		ctx: &PyContext,
		scale: f64,
	) -> PyResult<Self> {
		let encoder = sealy::CKKSEncoder::new(&ctx.inner, scale).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create CKKSEncoder: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: encoder,
		})
	}

	/// Returns the number of slots in this encoder produces.
	pub fn get_slot_count(&self) -> usize {
		self.inner.get_slot_count()
	}

	/// Encodes the given data into a plaintext.
	pub fn encode_float(
		&self,
		data: Vec<f64>,
	) -> PyResult<PyPlaintext> {
		let encoded = self.inner.encode_f64(&data).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encode data: {:?}",
				e
			))
		})?;
		Ok(PyPlaintext {
			inner: encoded,
		})
	}

	/// Decodes the given plaintext into data.
	pub fn decode_float(
		&self,
		plaintext: &PyPlaintext,
	) -> PyResult<Vec<f64>> {
		let decoded = self.inner.decode_f64(&plaintext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decode data: {:?}",
				e
			))
		})?;
		Ok(decoded)
	}
}
