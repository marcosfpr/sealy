use pyo3::prelude::*;

use crate::{
	ciphertext::PyCiphertext, context::PyContext, keys::PyPublicKey, plaintext::PyPlaintext,
	poly_array::PyPolynomialArray,
};

/// The components to an asymmetric encryption.
#[derive(Debug)]
#[pyclass(module = "sealy", name = "AsymmetricComponents")]
pub struct PyAsymmetricComponents {
	inner: sealy::AsymmetricComponents,
}

#[pymethods]
impl PyAsymmetricComponents {
	/// Creates a new AsymmetricComponents object.
	#[new]
	pub fn new(
		u: PyPolynomialArray,
		e: PyPolynomialArray,
		r: PyPlaintext,
	) -> Self {
		Self {
			inner: sealy::AsymmetricComponents::new(u.inner, e.inner, r.inner),
		}
	}

	/// Returns the u component of the asymmetric encryption.
	pub fn get_u(&self) -> PyPolynomialArray {
		PyPolynomialArray {
			inner: self.inner.u.clone(),
		}
	}

	/// Returns the e component of the asymmetric encryption.
	pub fn get_e(&self) -> PyPolynomialArray {
		PyPolynomialArray {
			inner: self.inner.e.clone(),
		}
	}

	/// Returns the r component of the asymmetric encryption.
	pub fn get_r(&self) -> PyPlaintext {
		PyPlaintext {
			inner: self.inner.r.clone(),
		}
	}
}

/// Encrypts Plaintext objects into Ciphertext objects.
#[pyclass(module = "sealy", name = "Encryptor")]
pub struct PyEncryptor {
	pub(crate) inner: sealy::Encryptor<sealy::Asym>,
}

#[pymethods]
impl PyEncryptor {
	/// Creates an Encryptor instance initialized with the specified sealy::Context,
	/// public key, and secret key.
	///
	/// * `ctx` - The sealy::Context
	/// * `publicKey` - The public key
	/// * `secretKey` - The secret key
	#[new]
	pub fn new(
		ctx: &PyContext,
		public_key: &PyPublicKey,
	) -> PyResult<Self> {
		let encryptor =
			sealy::Encryptor::with_public_key(&ctx.inner, &public_key.inner).map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to create encryptor with public and secret key: {:?}",
					e
				))
			})?;
		Ok(Self {
			inner: encryptor,
		})
	}

	/// Encrypts a plaintext with the public key and returns the ciphertext as
	/// a serializable object.
	pub fn encrypt(
		&self,
		plaintext: &PyPlaintext,
	) -> PyResult<PyCiphertext> {
		let ciphertext = self.inner.encrypt(&plaintext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encrypt plaintext: {:?}",
				e
			))
		})?;
		Ok(PyCiphertext {
			inner: ciphertext,
		})
	}

	/// Encrypts a plaintext with the public key and returns the ciphertext
	/// and the components used in the encryption.
	pub fn encrypt_return_components(
		&self,
		plaintext: &PyPlaintext,
	) -> PyResult<(PyCiphertext, PyAsymmetricComponents)> {
		let (ciphertext, components) = self
			.inner
			.encrypt_return_components(&plaintext.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to encrypt plaintext and return components: {:?}",
					e
				))
			})?;
		Ok((
			PyCiphertext {
				inner: ciphertext,
			},
			PyAsymmetricComponents {
				inner: components,
			},
		))
	}
}
