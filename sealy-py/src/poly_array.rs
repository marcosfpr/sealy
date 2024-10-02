use pyo3::prelude::*;

use crate::{
	ciphertext::PyCiphertext,
	context::PyContext,
	keys::{PyPublicKey, PySecretKey},
};

/// A SEAL array storing a number of polynomials.
#[derive(Debug, Clone, PartialEq)]
#[pyclass(module = "sealy", name = "PolynomialArray")]
pub struct PyPolynomialArray {
	pub(crate) inner: sealy::PolynomialArray,
}

#[pymethods]
impl PyPolynomialArray {
	/// Creates a new empty polynomial array. Use an encoder to populate with a value.
	#[new]
	pub fn new() -> PyResult<Self> {
		let poly_array = sealy::PolynomialArray::new().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create polynomial array: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: poly_array,
		})
	}

	/// Creates a polynomial array from a reference to a ciphertext.
	#[staticmethod]
	pub fn from_ciphertext(
		context: &PyContext,
		ciphertext: &PyCiphertext,
	) -> PyResult<Self> {
		let poly_array =
			sealy::PolynomialArray::new_from_ciphertext(&context.inner, &ciphertext.inner)
				.map_err(|e| {
					PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
						"Failed to create polynomial array from ciphertext: {:?}",
						e
					))
				})?;
		Ok(Self {
			inner: poly_array,
		})
	}

	/// Creates a polynomial array from a reference to a public key.
	#[staticmethod]
	pub fn from_public_key(
		context: &PyContext,
		public_key: &PyPublicKey,
	) -> PyResult<Self> {
		let poly_array =
			sealy::PolynomialArray::new_from_public_key(&context.inner, &public_key.inner)
				.map_err(|e| {
					PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
						"Failed to create polynomial array from public key: {:?}",
						e
					))
				})?;
		Ok(Self {
			inner: poly_array,
		})
	}

	/// Creates a polynomial array from a reference to a secret key.
	#[staticmethod]
	pub fn from_secret_key(
		context: &PyContext,
		secret_key: &PySecretKey,
	) -> PyResult<Self> {
		let poly_array =
			sealy::PolynomialArray::new_from_secret_key(&context.inner, &secret_key.inner)
				.map_err(|e| {
					PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
						"Failed to create polynomial array from secret key: {:?}",
						e
					))
				})?;
		Ok(Self {
			inner: poly_array,
		})
	}

	/// Has the array data been loaded? When an array is created, it initially
	/// has no data. Once data is loaded this is true. Additionally data can only
	/// be loaded once.
	pub fn is_reserved(&self) -> bool {
		self.inner.is_reserved()
	}

	/// Is the array in RNS form (true).
	pub fn is_rns(&self) -> bool {
		self.inner.is_rns()
	}

	/// Is the array in RNS form (true).
	pub fn is_multiprecision(&self) -> bool {
		self.inner.is_multiprecision()
	}

	/// Converts the polynomial array into the RNS format regardless of its
	/// current format.
	pub fn to_rns(&self) {
		self.inner.to_rns();
	}

	/// Converts the polynomial array into the multiprecision format regardless
	/// of its current format.
	pub fn to_multiprecision(&self) {
		self.inner.to_multiprecision();
	}

	/// This will be in coefficient order; all the limbs with a given coefficient
	/// are stored together in least significant order.
	///
	/// The number of limbs equals the number of moduli in the coefficient
	/// modulus.
	pub fn as_multiprecision_bytes(&self) -> PyResult<Vec<u64>> {
		let data = self.inner.as_multiprecision_u64s().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get polynomial array as multiprecision bytes: {:?}",
				e
			))
		})?;
		Ok(data)
	}

	/// This will be in modulus order; all the values associated with a given
	/// moduli are stored together.
	///
	/// The number of limbs equals the number of moduli in the coefficient
	/// modulus.
	pub fn as_rns_bytes(&self) -> PyResult<Vec<u64>> {
		let data = self.inner.as_rns_u64s().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get polynomial array as RNS bytes: {:?}",
				e
			))
		})?;
		Ok(data)
	}

	/// Returns the polynomial array as a vector of integers.
	pub fn as_ints(&self) -> PyResult<Vec<u64>> {
		let data = self.inner.as_u64s().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get polynomial array as ints: {:?}",
				e
			))
		})?;
		Ok(data)
	}

	/// Returns the number of polynomials stored in the `PolynomialArray`.
	pub fn get_num_polynomials(&self) -> u64 {
		self.inner.num_polynomials()
	}

	/// Returns the number of coefficients in each polynomial in the `PolynomialArray`.
	pub fn get_poly_modulus_degree(&self) -> u64 {
		self.inner.poly_modulus_degree()
	}

	/// Returns how many moduli are in the coefficient modulus set.
	pub fn get_coeff_modulus_size(&self) -> u64 {
		self.inner.coeff_modulus_size()
	}

	/// Reduces the polynomial array by dropping the last modulus in the modulus
	/// set.
	pub fn drop_modulus(&self) -> PyResult<Self> {
		let poly = self.inner.drop_modulus().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to drop modulus: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: poly,
		})
	}
}
