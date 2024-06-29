use pyo3::prelude::*;

#[pyclass(name = "SchemeType")]
#[derive(Debug, Clone)]
pub struct PySchemeType {
	inner: sealy::SchemeType,
}

#[pymethods]
impl PySchemeType {
	#[new]
	pub fn new(val: u8) -> Self {
		Self {
			inner: sealy::SchemeType::from_u8(val),
		}
	}

	#[staticmethod]
	pub fn bfv() -> Self {
		Self {
			inner: sealy::SchemeType::Bfv,
		}
	}

	#[staticmethod]
	pub fn ckks() -> Self {
		Self {
			inner: sealy::SchemeType::Ckks,
		}
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __eq__(&self, other: &PySchemeType) -> bool {
		self.inner == other.inner
	}
}

#[pyclass(name = "EncryptionParameters")]
#[derive(Debug)]
pub struct PyEncryptionParameters {
	pub(crate) inner: sealy::EncryptionParameters,
}

#[pymethods]
impl PyEncryptionParameters {
	#[new]
	pub fn new(scheme: PySchemeType) -> PyResult<Self> {
		let params = sealy::EncryptionParameters::new(scheme.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error creating parameters: {}",
				e
			))
		})?;

		Ok(Self {
			inner: params,
		})
	}

	#[staticmethod]
	pub const fn get_block_size() -> u8 {
		sealy::EncryptionParameters::block_size()
	}

	pub fn get_poly_modulus_degree(&self) -> u64 {
		self.inner.get_poly_modulus_degree()
	}

	pub fn get_scheme(&self) -> PySchemeType {
		PySchemeType {
			inner: self.inner.get_scheme(),
		}
	}

	pub fn get_plain_modulus(&self) -> PyModulus {
		PyModulus {
			inner: self.inner.get_plain_modulus(),
		}
	}

	pub fn get_coefficient_modulus(&self) -> Vec<PyModulus> {
		self.inner
			.get_coefficient_modulus()
			.into_iter()
			.map(|m| PyModulus {
				inner: m,
			})
			.collect()
	}

	pub fn get_parms_id(&self) -> u64 {
		self.inner.get_parms_id()
	}

	pub fn set_coefficient_modulus(&mut self, modulus: Vec<PyModulus>) -> PyResult<()> {
		self.inner
			.set_coefficient_modulus(modulus.into_iter().map(|m| m.inner).collect())
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyException, _>(format!(
					"Error setting coefficient modulus: {}",
					e
				))
			})
	}

	pub fn set_poly_modulus_degree(&mut self, degree: PyDegreeType) -> PyResult<()> {
		self.inner
			.set_poly_modulus_degree(degree.inner.into())
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyException, _>(format!(
					"Error setting poly modulus degree: {}",
					e
				))
			})
	}

	pub fn set_plain_modulus(&mut self, modulus: PyModulus) -> PyResult<()> {
		self.inner.set_plain_modulus(modulus.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error setting plain modulus: {}",
				e
			))
		})
	}

	pub fn set_plain_modulus_constant(&mut self, modulus: u64) -> PyResult<()> {
		self.inner.set_plain_modulus_u64(modulus).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error setting plain modulus: {}",
				e
			))
		})
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}
}

#[pyclass(name = "CoefficientModulus")]
#[derive(Debug)]
pub struct PyCoefficientModulus;

#[pymethods]
impl PyCoefficientModulus {
	#[staticmethod]
	pub fn create(degree: PyDegreeType, bit_sizes: Vec<i32>) -> PyResult<Vec<PyModulus>> {
		let modulus = sealy::CoefficientModulus::create(degree.inner, &bit_sizes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error creating CoefficientModulus: {}",
				e
			))
		})?;
		Ok(modulus
			.into_iter()
			.map(|m| PyModulus {
				inner: m,
			})
			.collect())
	}

	#[staticmethod]
	pub fn ckks(degree: PyDegreeType, bit_sizes: Vec<i32>) -> PyResult<Vec<PyModulus>> {
		Self::create(degree, bit_sizes)
	}

	#[staticmethod]
	pub fn bfv(degree: PyDegreeType, security_level: PySecurityLevel) -> PyResult<Vec<PyModulus>> {
		let modulus = sealy::CoefficientModulus::bfv_default(degree.inner, security_level.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyException, _>(format!(
					"Error creating CoefficientModulus: {}",
					e
				))
			})?;
		Ok(modulus
			.into_iter()
			.map(|m| PyModulus {
				inner: m,
			})
			.collect())
	}

	#[staticmethod]
	pub fn max_bit_count(degree: PyDegreeType, security_level: PySecurityLevel) -> u32 {
		sealy::CoefficientModulus::max_bit_count(degree.inner.into(), security_level.inner)
	}
}

#[pyclass(name = "PlainModulus")]
pub struct PyPlainModulus;

#[pymethods]
impl PyPlainModulus {
	#[staticmethod]
	pub fn batching(degree: PyDegreeType, bit_size: u32) -> PyResult<PyModulus> {
		let modulus = sealy::PlainModulus::batching(degree.inner, bit_size).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!("Error creating Modulus: {}", e))
		})?;
		Ok(PyModulus {
			inner: modulus,
		})
	}

	#[staticmethod]
	pub fn raw(val: u64) -> PyResult<PyModulus> {
		let modulus = sealy::PlainModulus::raw(val).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!("Error creating Modulus: {}", e))
		})?;
		Ok(PyModulus {
			inner: modulus,
		})
	}
}

#[pyclass(name = "Modulus")]
#[derive(Debug, Clone)]
pub struct PyModulus {
	inner: sealy::Modulus,
}

#[pymethods]
impl PyModulus {
	#[new]
	pub fn new(value: u64) -> PyResult<Self> {
		let inner = sealy::Modulus::new(value).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!("Error creating Modulus: {}", e))
		})?;
		Ok(Self {
			inner,
		})
	}

	pub fn get_value(&self) -> u64 {
		self.inner.value()
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __eq__(&self, other: &PyModulus) -> bool {
		self.inner == other.inner
	}
}

#[pyclass(name = "DegreeType")]
#[derive(Debug, Clone)]
pub struct PyDegreeType {
	inner: sealy::DegreeType,
}

#[pymethods]
impl PyDegreeType {
	#[new]
	pub fn new(degree: u64) -> PyResult<Self> {
		let degree = sealy::DegreeType::try_from(degree).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error creating DegreeType: {}. \
                Expected one of [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]",
				e
			))
		})?;

		Ok(Self {
			inner: degree,
		})
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __eq__(&self, other: &PyDegreeType) -> bool {
		self.inner == other.inner
	}
}

#[pyclass(name = "SecurityLevel")]
#[derive(Debug, Clone)]
pub struct PySecurityLevel {
	pub(crate) inner: sealy::SecurityLevel,
}

#[pymethods]
impl PySecurityLevel {
	#[new]
	pub fn new(value: i32) -> PyResult<Self> {
		let level = sealy::SecurityLevel::try_from(value).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyException, _>(format!(
				"Error creating SecurityLevel: {}",
				e
			))
		})?;

		Ok(Self {
			inner: level,
		})
	}

	#[staticmethod]
	pub fn default() -> Self {
		Self {
			inner: sealy::SecurityLevel::default(),
		}
	}

	pub fn get_value(&self) -> i32 {
		self.inner.into()
	}

	fn __str__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __repr__(&self) -> String {
		format!("{:?}", self.inner)
	}

	fn __eq__(&self, other: &PySecurityLevel) -> bool {
		self.inner == other.inner
	}
}
