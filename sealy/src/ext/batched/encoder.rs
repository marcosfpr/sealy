use super::Batch;
use crate::{Encoder, Plaintext, Result, SlotCount};

/// An encoder that encodes data in batches.
#[derive(Clone)]
pub struct BatchEncoder<T, E> {
	encoder: E,
	data_type: std::marker::PhantomData<T>,
}

impl<T, E> BatchEncoder<T, E>
where
	E: Encoder<T>,
{
	/// Creates a new BatchEncoder.
	pub fn new(encoder: E) -> Self {
		Self {
			encoder,
			data_type: std::marker::PhantomData,
		}
	}
}

impl<T, E> SlotCount for BatchEncoder<T, E>
where
	E: Encoder<T>,
{
	/// Returns the number of slots in this encoder produces.
	fn get_slot_count(&self) -> usize {
		self.encoder.get_slot_count()
	}
}

impl<T, E> Encoder<T> for BatchEncoder<T, E>
where
	E: Encoder<T>,
	E::Encoded: Into<Plaintext>,
	for<'a> &'a E::Encoded: From<&'a Plaintext>,
{
	type Encoded = Batch<Plaintext>;

	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	fn encode(&self, data: &[T]) -> Result<Self::Encoded> {
		let mut plaintexts = Vec::new();

		let batch_size = self.get_slot_count();

		for chunk in data.chunks(batch_size) {
			let plaintext = self.encoder.encode(chunk)?;
			plaintexts.push(plaintext.into());
		}

		Ok(Batch(plaintexts))
	}

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `batch` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	fn decode(&self, batch: &Self::Encoded) -> Result<Vec<T>> {
		let mut data = Vec::new();

		for plaintext in batch {
			let decoded = self.encoder.decode(plaintext.into())?;
			data.extend(decoded);
		}

		Ok(data)
	}
}

#[cfg(test)]
mod tests {

	use crate::{
		BFVEncoder, BfvEncryptionParametersBuilder, CoefficientModulus, Context, DegreeType,
		Encoder, PlainModulus, SecurityLevel,
	};

	use crate::ext::batched::encoder::BatchEncoder;

	#[test]
	fn can_get_encode_and_decode_unsigned() {
		let params = BfvEncryptionParametersBuilder::new()
			.set_poly_modulus_degree(DegreeType::D8192)
			.set_coefficient_modulus(
				CoefficientModulus::create(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
			)
			.set_plain_modulus(PlainModulus::batching(DegreeType::D8192, 20).unwrap())
			.build()
			.unwrap();

		let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();

		let bfv_encoder = BFVEncoder::<i64>::new(&ctx).unwrap();

		let encoder = BatchEncoder::new(bfv_encoder);

		let mut data = Vec::with_capacity(32_768);

		for i in 0..32_768 {
			data.push(i as i64);
		}

		let plaintext = encoder.encode(data.as_slice()).unwrap();
		let data_2: Vec<i64> = encoder.decode(&plaintext).unwrap();

		assert_eq!(data, data_2);
	}
}
