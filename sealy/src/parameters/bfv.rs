use crate::{DegreeType, EncryptionParameters, Error, Modulus, ModulusDegreeType, SchemeType};

use super::{CoefficientModulusType, PlainModulusType};

/// Represents a builder that sets up and creates encryption scheme parameters.
/// The parameters (most importantly PolyModulus, CoeffModulus, PlainModulus)
/// significantly affect the performance, capabilities, and security of the
/// encryption scheme.
pub struct BfvEncryptionParametersBuilder {
	poly_modulus_degree: ModulusDegreeType,
	coefficient_modulus: CoefficientModulusType,
	plain_modulus: PlainModulusType,
}

impl BfvEncryptionParametersBuilder {
	/// Creates a new builder.
	pub fn new() -> Self {
		Self {
			poly_modulus_degree: ModulusDegreeType::NotSet,
			coefficient_modulus: CoefficientModulusType::NotSet,
			plain_modulus: PlainModulusType::NotSet,
		}
	}

	/// Set the degree of the polynomial used in the BFV scheme. Genrally,
	/// larger values provide more security and noise margin at the expense
	/// of performance.
	pub fn set_poly_modulus_degree(mut self, degree: DegreeType) -> Self {
		self.poly_modulus_degree = ModulusDegreeType::Constant(degree);
		self
	}

	/// Sets the coefficient modulus parameter. The coefficient modulus consists
	/// of a list of distinct prime numbers, and is represented by a vector of
	/// Modulus objects. The coefficient modulus directly affects the size
	/// of ciphertext elements, the amount of computation that the scheme can
	/// perform (bigger is better), and the security level (bigger is worse). In
	/// Microsoft SEAL each of the prime numbers in the coefficient modulus must
	/// be at most 60 bits, and must be congruent to 1 modulo 2*poly_modulus_degree.
	pub fn set_coefficient_modulus(mut self, modulus: Vec<Modulus>) -> Self {
		self.coefficient_modulus = CoefficientModulusType::Modulus(modulus);
		self
	}

	/// Set the plaintext modulus to a fixed size. Not recommended.
	/// Ideally, create a PlainModulus to set up batching and call
	/// set_plain_modulus.
	pub fn set_plain_modulus_u64(mut self, modulus: u64) -> Self {
		self.plain_modulus = PlainModulusType::Constant(modulus);
		self
	}

	/// Set the plaintext modulus. This method enables batching, use
	/// `PlainModulus::batching()` to create a suitable modulus chain.
	pub fn set_plain_modulus(mut self, modulus: Modulus) -> Self {
		self.plain_modulus = PlainModulusType::Modulus(modulus);
		self
	}

	/// Validate the parameter choices and return the encryption parameters.
	pub fn build(self) -> Result<EncryptionParameters, Error> {
		let mut params = EncryptionParameters::new(SchemeType::Bfv)?;

		params.set_poly_modulus_degree(self.poly_modulus_degree.try_into()?)?;

		match self.coefficient_modulus {
			CoefficientModulusType::NotSet => return Err(Error::CoefficientModulusNotSet),
			CoefficientModulusType::Modulus(m) => params.set_coefficient_modulus(m)?,
		};

		match self.plain_modulus {
			PlainModulusType::NotSet => return Err(Error::PlainModulusNotSet),
			PlainModulusType::Constant(p) => {
				params.set_plain_modulus_u64(p)?;
			}
			PlainModulusType::Modulus(m) => {
				params.set_plain_modulus(m)?;
			}
		};

		Ok(params)
	}
}

impl Default for BfvEncryptionParametersBuilder {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn can_build_params() {
		let params = BfvEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D1024)
			.set_coefficient_modulus(
				CoefficientModulus::bfv_default(DegreeType::D1024, SecurityLevel::default())
					.unwrap(),
			)
			.set_plain_modulus_u64(1234)
			.build()
			.unwrap();

		assert_eq!(params.get_poly_modulus_degree(), 1024);
		assert_eq!(params.get_scheme(), SchemeType::Bfv);
		assert_eq!(params.get_plain_modulus().value(), 1234);
		assert_eq!(params.get_coefficient_modulus().len(), 1);
		assert_eq!(params.get_coefficient_modulus()[0].value(), 132120577);

		let params = BfvEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D1024)
			.set_coefficient_modulus(
				CoefficientModulus::create(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus_u64(1234)
			.build()
			.unwrap();

		let modulus = params.get_coefficient_modulus();

		assert_eq!(params.get_poly_modulus_degree(), 1024);
		assert_eq!(params.get_scheme(), SchemeType::Bfv);
		assert_eq!(params.get_plain_modulus().value(), 1234);
		assert_eq!(modulus.len(), 5);
		assert_eq!(modulus[0].value(), 1125899905744897);
		assert_eq!(modulus[1].value(), 1073643521);
		assert_eq!(modulus[2].value(), 1073692673);
		assert_eq!(modulus[3].value(), 1125899906629633);
		assert_eq!(modulus[4].value(), 1125899906826241);
	}
}
