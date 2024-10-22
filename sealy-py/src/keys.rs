use pyo3::prelude::*;
use sealy::{FromBytes, ToBytes};

use crate::context::PyContext;

/// Class to store a public key.
#[derive(Debug, Clone)]
#[pyclass(module = "sealy", name = "PublicKey")]
pub struct PyPublicKey {
	pub(crate) inner: sealy::PublicKey,
}

#[pymethods]
impl PyPublicKey {
	/// Creates a new public key.
	#[new]
	pub fn new() -> PyResult<Self> {
		let pk = sealy::PublicKey::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create public key: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: pk,
		})
	}

	/// Returns public key as a byte array.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get public key as bytes: {:?}",
				e
			))
		})
	}

	/// Creates a new public key from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		bytes: Vec<u8>,
	) -> PyResult<Self> {
		let pk = sealy::PublicKey::from_bytes(&context.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create public key from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: pk,
		})
	}

	fn __eq__(
		&self,
		other: &PyPublicKey,
	) -> bool {
		self.inner == other.inner
	}
}

/// Class to store a secret key.
#[derive(Debug, Clone)]
#[pyclass(module = "sealy", name = "SecretKey")]
pub struct PySecretKey {
	pub(crate) inner: sealy::SecretKey,
}

#[pymethods]
impl PySecretKey {
	/// Creates a new secret key.
	#[new]
	pub fn new() -> PyResult<Self> {
		let sk = sealy::SecretKey::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create secret key: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: sk,
		})
	}

	/// Returns secret key as a byte array.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get secret key as bytes: {:?}",
				e
			))
		})
	}

	/// Creates a new secret key from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		bytes: Vec<u8>,
	) -> PyResult<Self> {
		let sk = sealy::SecretKey::from_bytes(&context.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create secret key from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: sk,
		})
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __eq__(
		&self,
		other: &PySecretKey,
	) -> bool {
		self.inner == other.inner
	}
}

/// Class to store relinearization keys.
#[derive(Debug, Clone)]
#[pyclass(module = "sealy", name = "RelinearizationKey")]
pub struct PyRelinearizationKey {
	pub(crate) inner: sealy::RelinearizationKey,
}

#[pymethods]
impl PyRelinearizationKey {
	#[new]
	pub fn new() -> PyResult<Self> {
		let rk = sealy::RelinearizationKey::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create relinearization keys: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: rk,
		})
	}

	/// Returns the key as a byte array.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get relinearization keys as bytes: {:?}",
				e
			))
		})
	}

	/// Creates a new relinearization keys from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		bytes: Vec<u8>,
	) -> PyResult<Self> {
		let rk = sealy::RelinearizationKey::from_bytes(&context.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create relinearization keys from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: rk,
		})
	}

	fn __eq__(
		&self,
		other: &PyRelinearizationKey,
	) -> bool {
		self.inner == other.inner
	}
}

/// Class to store Galois keys.
#[derive(Debug, Clone)]
#[pyclass(module = "sealy", name = "GaloisKey")]
pub struct PyGaloisKey {
	pub(crate) inner: sealy::GaloisKey,
}

#[pymethods]
impl PyGaloisKey {
	#[new]
	pub fn new() -> PyResult<Self> {
		let gk = sealy::GaloisKey::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create Galois keys: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: gk,
		})
	}

	/// Returns the key as a byte array.
	pub fn as_bytes(&self) -> PyResult<Vec<u8>> {
		self.inner.as_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get Galois keys as bytes: {:?}",
				e
			))
		})
	}

	/// Creates a new Galois keys from a byte array.
	#[staticmethod]
	pub fn from_bytes(
		context: &PyContext,
		bytes: Vec<u8>,
	) -> PyResult<Self> {
		let gk = sealy::GaloisKey::from_bytes(&context.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create Galois keys from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: gk,
		})
	}

	fn __eq__(
		&self,
		other: &PyGaloisKey,
	) -> bool {
		self.inner == other.inner
	}
}

/// Generates matching secret key and public key.
#[derive(Debug)]
#[pyclass(module = "sealy", name = "KeyGenerator")]
pub struct PyKeyGenerator {
	inner: sealy::KeyGenerator,
}

#[pymethods]
impl PyKeyGenerator {
	/// Creates a KeyGenerator initialized with the specified sealy::Context.
	#[new]
	pub fn new(ctx: &PyContext) -> PyResult<Self> {
		let gen = sealy::KeyGenerator::new(&ctx.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create key generator: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: gen,
		})
	}

	/// Creates an KeyGenerator instance initialized with the specified
	/// sealy::Context and specified previously secret key.
	#[staticmethod]
	pub fn from_secret_key(
		ctx: &PyContext,
		secret_key: &PySecretKey,
	) -> PyResult<Self> {
		let gen = sealy::KeyGenerator::new_from_secret_key(&ctx.inner, &secret_key.inner).map_err(
			|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to create key generator from secret key: {:?}",
					e
				))
			},
		)?;
		Ok(Self {
			inner: gen,
		})
	}

	/// Returns a copy of the secret key.
	pub fn secret_key(&self) -> PySecretKey {
		let sk = self.inner.secret_key();
		PySecretKey {
			inner: sk,
		}
	}

	/// Generates and returns a new public key.
	pub fn create_public_key(&self) -> PyPublicKey {
		let pk = self.inner.create_public_key();
		PyPublicKey {
			inner: pk,
		}
	}

	/// Creates relinearization keys
	pub fn create_relinearization_key(&self) -> PyResult<PyRelinearizationKey> {
		let rk = self.inner.create_relinearization_keys().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create relinearization keys: {:?}",
				e
			))
		})?;
		Ok(PyRelinearizationKey {
			inner: rk,
		})
	}

	/// Generates Galois keys and stores the result in destination.
	pub fn create_galois_key(&self) -> PyResult<PyGaloisKey> {
		let gk = self.inner.create_galois_keys().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create Galois keys: {:?}",
				e
			))
		})?;

		Ok(PyGaloisKey {
			inner: gk,
		})
	}
}
