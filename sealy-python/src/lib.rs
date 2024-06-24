use pyo3::prelude::*;

mod parameters;

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

	Ok(())
}
