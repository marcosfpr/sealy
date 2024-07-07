use crate::Context;
use crate::FromBytes;
use crate::Result;
use crate::ToBytes;

pub mod decryptor;
pub mod encoder;
pub mod encryptor;
pub mod evaluator;

/// Struct to store a batch of elements of the same type.
#[derive(Debug, Clone)]
pub struct Batch<T>(pub Vec<T>);

/// A trait for converting batch of objects into a list of byte arrays.
pub trait ToBatchedBytes {
	/// Returns the object as a byte array.
	fn as_batched_bytes(&self) -> Result<Vec<Vec<u8>>>;
}

/// A trait for converting data from a byte slice under a given SEAL context.
pub trait FromBatchedBytes {
	/// Deserialize an object from the given bytes using the given
	/// context.
	fn from_batched_bytes(context: &Context, batched: &[Vec<u8>]) -> Result<Self>
	where
		Self: Sized;
}

impl<T> IntoIterator for Batch<T> {
	type Item = T;
	type IntoIter = std::vec::IntoIter<T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T> IntoIterator for &'a Batch<T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl<T> Batch<T> {
	/// Returns the first element in this batch.
	pub fn first(&self) -> Option<&T> {
		self.get(0)
	}

	/// Returns the element given by the index.
	pub fn get(&self, index: usize) -> Option<&T> {
		self.0.get(index)
	}

	/// Returns the number of elements in this batch.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Returns true if this batch contains no elements.
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Returns an iterator over the elements of this batch.
	pub fn iter(&self) -> std::slice::Iter<T> {
		self.0.iter()
	}

	/// Returns a mutable iterator over the elements of this batch.
	pub fn iter_mut(&mut self) -> std::slice::IterMut<T> {
		self.0.iter_mut()
	}

	/// Applies the given function to each element in this batch, returning a new batch with the results.
	pub fn map<U, F>(&self, f: F) -> Batch<U>
	where
		F: FnMut(&T) -> U,
	{
		Batch(self.0.iter().map(f).collect())
	}

	/// zips two batches together, applying the given function to each pair of elements.
	pub fn zip<U, V, F>(&self, other: &Batch<U>, mut f: F) -> Batch<V>
	where
		F: FnMut(&T, &U) -> V,
	{
		Batch(
			self.0
				.iter()
				.zip(other.0.iter())
				.map(|(a, b)| f(a, b))
				.collect(),
		)
	}
}

impl<T> FromBatchedBytes for Batch<T>
where
	T: FromBytes,
{
	fn from_batched_bytes(context: &Context, batched: &[Vec<u8>]) -> Result<Self> {
		let values = batched
			.iter()
			.map(|bytes| T::from_bytes(context, bytes))
			.collect::<Result<Vec<_>>>()?;
		Ok(Batch(values))
	}
}

impl<T> ToBatchedBytes for Batch<T>
where
	T: ToBytes,
{
	fn as_batched_bytes(&self) -> Result<Vec<Vec<u8>>> {
		self.0.iter().map(|value| value.as_bytes()).collect()
	}
}

impl<T> Batch<T>
where
	T: Clone,
{
	/// Returns a cloned copy of the element given by the index.
	pub fn get_cloned(&self, index: usize) -> Option<T> {
		self.get(index).cloned()
	}
}

impl<T, E> Batch<std::result::Result<T, E>> {
	/// Collects the results in this batch, returning the successful values.
	pub fn collect(self) -> std::result::Result<Batch<T>, E> {
		let values = self
			.0
			.into_iter()
			.collect::<std::result::Result<Vec<_>, _>>()?;
		Ok(Batch(values))
	}
}
