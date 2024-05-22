use crate::encoder::Encoder;

pub struct TensorEncoder<T, E: Encoder<T>> {
	encoder: E,
	data_type: std::marker::PhantomData<T>,
}
