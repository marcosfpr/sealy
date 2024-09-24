use crate::poly_array::PolynomialArray;
use crate::Plaintext;

mod sealed {
	pub trait Sealed {}
	impl Sealed for super::Sym {}
	impl Sealed for super::Asym {}
	impl Sealed for super::SymAsym {}
}

/// Marker traits to signify what types of enryptions are supported
pub mod marker {
	/// Supports symmetric encryptions.
	pub trait Sym: super::sealed::Sealed {}
	/// Supports asymmetric encryptions.
	pub trait Asym: super::sealed::Sealed {}
}

/// Symmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Sym;
impl marker::Sym for Sym {}

/// Asymmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Asym;
impl marker::Asym for Asym {}

/// Both symmetric and asymmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymAsym;
impl marker::Sym for SymAsym {}
impl marker::Asym for SymAsym {}

/// The components to an asymmetric encryption.
pub struct AsymmetricComponents {
	/// Uniform ternary polynomial.
	///
	/// This polynomial array should always have size one, i.e. it is a single
	/// polynomial.
	pub u: PolynomialArray,
	/// Error polynomial.
	///
	/// This will generally have length two, if relinearization is performed after every
	/// multiplication.
	pub e: PolynomialArray,
	/// Rounding component after scaling the message by delta.
	pub r: Plaintext,
}

impl AsymmetricComponents {
	/// Create a new AsymmetricComponents instance.
	pub fn new(
		u: PolynomialArray,
		e: PolynomialArray,
		r: Plaintext,
	) -> Self {
		Self {
			u,
			e,
			r,
		}
	}
}

/// The components to a symmetric encryption.
pub struct SymmetricComponents {
	/// Error polynomial.
	///
	/// This polynomial array should always have size one, i.e. it is a single
	/// polynomial.
	pub e: PolynomialArray,
	/// Rounding component after scaling the message by delta.
	pub r: Plaintext,
}

impl SymmetricComponents {
	/// Create a new SymmetricComponents instance.
	pub fn new(
		e: PolynomialArray,
		r: Plaintext,
	) -> Self {
		Self {
			e,
			r,
		}
	}
}

impl core::fmt::Debug for AsymmetricComponents {
	fn fmt(
		&self,
		f: &mut core::fmt::Formatter,
	) -> core::fmt::Result {
		f.debug_struct("AsymmetricComponents")
			.field("u", &"<ELIDED>")
			.field("e", &"<ELIDED>")
			.field("r", &"<ELIDED>")
			.finish()
	}
}

impl core::fmt::Debug for SymmetricComponents {
	fn fmt(
		&self,
		f: &mut core::fmt::Formatter,
	) -> core::fmt::Result {
		f.debug_struct("SymmetricComponents")
			.field("e", &"<ELIDED>")
			.field("r", &"<ELIDED>")
			.finish()
	}
}
