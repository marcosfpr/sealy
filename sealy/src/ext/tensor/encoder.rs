use super::Tensor;
use crate::{BFVEncoder, CKKSEncoder, Plaintext, Result};

/// An encoder that encodes data in tensors.
#[derive(Clone)]
pub struct TensorEncoder<E> {
	encoder: E,
}

impl<E> TensorEncoder<E> {
	/// Creates a new tensor encoder.
	pub fn new(encoder: E) -> Self {
		Self {
			encoder,
		}
	}
}

impl TensorEncoder<CKKSEncoder> {
	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	pub fn encode_f64(
		&self,
		data: &[f64],
	) -> Result<Tensor<Plaintext>> {
		let mut plaintexts = Vec::new();

		let chunk_size = self.get_slot_count();

		for chunk in data.chunks(chunk_size) {
			let plaintext = self.encoder.encode_f64(chunk)?;
			plaintexts.push(plaintext);
		}

		Ok(Tensor(plaintexts))
	}

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `chunk` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	pub fn decode_f64(
		&self,
		chunk: &Tensor<Plaintext>,
	) -> Result<Vec<f64>> {
		let mut data = Vec::new();

		for plaintext in chunk {
			let decoded = self.encoder.decode_f64(plaintext)?;
			data.extend(decoded);
		}

		Ok(data)
	}

	/// Returns the number of slots in this encoder produces.
	pub fn get_slot_count(&self) -> usize {
		self.encoder.get_slot_count()
	}
}

impl TensorEncoder<BFVEncoder> {
	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	pub fn encode_i64(
		&self,
		data: &[i64],
	) -> Result<Tensor<Plaintext>> {
		let mut plaintexts = Vec::new();

		let chunk_size = self.get_slot_count();

		for chunk in data.chunks(chunk_size) {
			let plaintext = self.encoder.encode_i64(chunk)?;
			plaintexts.push(plaintext);
		}

		Ok(Tensor(plaintexts))
	}

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `chunk` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	pub fn decode_i64(
		&self,
		chunk: &Tensor<Plaintext>,
	) -> Result<Vec<i64>> {
		let mut data = Vec::new();

		for plaintext in chunk {
			let decoded = self.encoder.decode_i64(plaintext)?;
			data.extend(decoded);
		}

		Ok(data)
	}

	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	pub fn encode_u64(
		&self,
		data: &[u64],
	) -> Result<Tensor<Plaintext>> {
		let mut plaintexts = Vec::new();

		let chunk_size = self.get_slot_count();

		for chunk in data.chunks(chunk_size) {
			let plaintext = self.encoder.encode_u64(chunk)?;
			plaintexts.push(plaintext);
		}

		Ok(Tensor(plaintexts))
	}

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `chunk` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	pub fn decode_u64(
		&self,
		chunk: &Tensor<Plaintext>,
	) -> Result<Vec<u64>> {
		let mut data = Vec::new();

		for plaintext in chunk {
			let decoded = self.encoder.decode_u64(plaintext)?;
			data.extend(decoded);
		}

		Ok(data)
	}

	/// Returns the number of slots in this encoder produces.
	pub fn get_slot_count(&self) -> usize {
		self.encoder.get_slot_count()
	}
}

#[cfg(test)]
mod tests {

	use crate::{
		ext::tensor::encoder::TensorEncoder, BFVEncoder, BFVEncryptionParametersBuilder,
		CoefficientModulusFactory, Context, DegreeType, PlainModulusFactory, SecurityLevel,
	};

	#[test]
	fn can_get_encode_and_decode_unsigned() {
		let params = BFVEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D8192)
			.set_coefficient_modulus(
				CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus(PlainModulusFactory::batching(DegreeType::D8192, 20).unwrap())
			.build()
			.unwrap();

		let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

		let bfv_encoder = BFVEncoder::new(&ctx).unwrap();

		let encoder = TensorEncoder::new(bfv_encoder);

		let mut data = Vec::with_capacity(32_768);

		for i in 0..32_768 {
			data.push(i as i64);
		}

		let plaintext = encoder.encode_i64(data.as_slice()).unwrap();
		let data_2: Vec<i64> = encoder.decode_i64(&plaintext).unwrap();

		assert_eq!(data, data_2);
	}
}
