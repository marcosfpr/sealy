use std::hash::Hash;

use pyo3::prelude::*;
use sealy::{FromBytes, ToBytes};

use crate::{context::PyContext, memory::PyMemoryPool};

/// Class to store a plaintext element. The data for the plaintext is
/// a polynomial with coefficients modulo the plaintext modulus.
#[derive(Debug, Clone, PartialEq, Hash)]
#[pyclass(module = "sealy", name = "Plaintext")]
pub struct PyPlaintext {
	pub(crate) inner: sealy::Plaintext,
}

#[pymethods]
impl PyPlaintext {
	/// Constructs an empty plaintext allocating no memory.
	#[new]
	pub fn new() -> PyResult<Self> {
		let plaintext = sealy::Plaintext::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create plaintext: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: plaintext,
		})
	}

	/// Constructs an empty plaintext in a memory pool.
	#[staticmethod]
	pub fn with_pool(memory: &PyMemoryPool) -> PyResult<Self> {
		let plaintext = sealy::Plaintext::new_with_pool(&memory.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create plaintext with memory pool: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: plaintext,
		})
	}

	/// Constructs a plaintext from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		data: Vec<u8>,
	) -> PyResult<Self> {
		let plaintext = sealy::Plaintext::from_bytes(&context.inner, &data).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create plaintext from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: plaintext,
		})
	}

	/// Generates a bytearray representation of the plaintext.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get plaintext as bytes: {:?}",
				e
			))
		})
	}

	/// Constructs a plaintext from a given hexadecimal string describing the
	/// plaintext polynomial.
	#[staticmethod]
	pub fn from_hex_string(hex_str: &str) -> PyResult<Self> {
		let plaintext = sealy::Plaintext::from_hex_string(hex_str).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create plaintext with hex string: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: plaintext,
		})
	}

	/// Gets the coefficient at the given location. Coefficients are ordered
	/// from lowest to highest degree, with the first value being the constant
	/// coefficient.
	pub fn get_coefficient(
		&self,
		index: usize,
	) -> u64 {
		self.inner.get_coefficient(index)
	}

	/// Sets the coefficient at the given location. Coefficients are ordered
	/// from lowest to highest degree, with the first value being the constant
	/// coefficient.
	pub fn set_coefficient(
		&mut self,
		index: usize,
		value: u64,
	) {
		self.inner.set_coefficient(index, value);
	}

	/// Sets the number of coefficients this plaintext can hold.
	pub fn resize(
		&mut self,
		count: usize,
	) {
		self.inner.resize(count);
	}

	/// Returns the number of coefficients this plaintext can hold.
	pub fn size(&self) -> usize {
		self.inner.len()
	}

	/// Returns whether the plaintext is in NTT form.
	pub fn is_ntt_form(&self) -> bool {
		self.inner.is_ntt_form()
	}

	fn __len__(&self) -> usize {
		self.size()
	}

	fn __eq__(
		&self,
		other: &PyPlaintext,
	) -> bool {
		self.inner == other.inner
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}
}
