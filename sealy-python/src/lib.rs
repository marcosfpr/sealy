use pyo3::prelude::*;

mod context;
mod context_data;
mod keys;
mod parameters;

use crate::context::PyContext;
use crate::context_data::PyContextData;
use crate::keys::{PyGaloisKey, PyKeyGenerator, PyPublicKey, PyRelinearizationKey, PySecretKey};
use crate::parameters::{
	PyCoefficientModulus, PyDegreeType, PyEncryptionParameters, PyModulus, PyPlainModulus,
	PySchemeType, PySecurityLevel,
};

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn sealy(m: &Bound<'_, PyModule>) -> PyResult<()> {
	m.add_class::<PySchemeType>()?;
	m.add_class::<PyDegreeType>()?;
	m.add_class::<PySecurityLevel>()?;
	m.add_class::<PyModulus>()?;
	m.add_class::<PyPlainModulus>()?;
	m.add_class::<PyCoefficientModulus>()?;
	m.add_class::<PyEncryptionParameters>()?;
	m.add_class::<PyContextData>()?;
	m.add_class::<PyContext>()?;
	m.add_class::<PyPublicKey>()?;
	m.add_class::<PySecretKey>()?;
	m.add_class::<PyKeyGenerator>()?;
	m.add_class::<PyGaloisKey>()?;
	m.add_class::<PyRelinearizationKey>()?;

	Ok(())
}
