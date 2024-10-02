use crate::Context;
use crate::FromBytes;
use crate::Result;
use crate::ToBytes;

pub mod decryptor;
pub mod encoder;
pub mod encryptor;
pub mod evaluator;

/// Struct to store a tensor of elements of the same type.
#[derive(Debug, Clone)]
pub struct Tensor<T>(pub Vec<T>);

/// A trait for converting chunk of objects into a list of byte arrays.
pub trait ToChunk {
	/// Returns the object as a byte array.
	fn to_chunk(&self) -> Result<Vec<Vec<u8>>>;
}

/// A trait for converting data from a byte slice under a given SEAL context.
pub trait FromChunk {
	/// Deserialize an object from the given bytes using the given
	/// context.
	fn from_chunk(
		context: &Context,
		chunk: &[Vec<u8>],
	) -> Result<Self>
	where
		Self: Sized;
}

impl<T> IntoIterator for Tensor<T> {
	type Item = T;
	type IntoIter = std::vec::IntoIter<T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T> IntoIterator for &'a Tensor<T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl<T> Tensor<T> {
	/// Returns the first element in this tensor.
	pub fn first(&self) -> Option<&T> {
		self.get(0)
	}

	/// Returns the element given by the index.
	pub fn get(
		&self,
		index: usize,
	) -> Option<&T> {
		self.0.get(index)
	}

	/// Returns the number of elements in this tensor.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Returns true if this tensor contains no elements.
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Returns an iterator over the elements of this tensor.
	pub fn iter(&self) -> std::slice::Iter<T> {
		self.0.iter()
	}

	/// Returns a mutable iterator over the elements of this tensor.
	pub fn iter_mut(&mut self) -> std::slice::IterMut<T> {
		self.0.iter_mut()
	}

	/// Applies the given function to each element in this tensor, returning a new tensor with the results.
	pub fn map<U, F>(
		&self,
		f: F,
	) -> Tensor<U>
	where
		F: FnMut(&T) -> U,
	{
		Tensor(self.0.iter().map(f).collect())
	}

	/// zips two tensors together, applying the given function to each pair of elements.
	pub fn zip<U, V, F>(
		&self,
		other: &Tensor<U>,
		mut f: F,
	) -> Tensor<V>
	where
		F: FnMut(&T, &U) -> V,
	{
		Tensor(
			self.0
				.iter()
				.zip(other.0.iter())
				.map(|(a, b)| f(a, b))
				.collect(),
		)
	}
}

impl<T> FromChunk for Tensor<T>
where
	T: FromBytes<State = Context>,
{
	fn from_chunk(
		context: &Context,
		chunks: &[Vec<u8>],
	) -> Result<Self> {
		let values = chunks
			.iter()
			.map(|bytes| T::from_bytes(context, bytes))
			.collect::<Result<Vec<_>>>()?;
		Ok(Tensor(values))
	}
}

impl<T> ToChunk for Tensor<T>
where
	T: ToBytes,
{
	fn to_chunk(&self) -> Result<Vec<Vec<u8>>> {
		self.0.iter().map(|value| value.as_bytes()).collect()
	}
}

impl<T> Tensor<T>
where
	T: Clone,
{
	/// Returns a cloned copy of the element given by the index.
	pub fn get_cloned(
		&self,
		index: usize,
	) -> Option<T> {
		self.get(index).cloned()
	}
}

impl<T, E> Tensor<std::result::Result<T, E>> {
	/// Collects the results in this tensor, returning the successful values.
	pub fn collect(self) -> std::result::Result<Tensor<T>, E> {
		let values = self
			.0
			.into_iter()
			.collect::<std::result::Result<Vec<_>, _>>()?;
		Ok(Tensor(values))
	}
}
