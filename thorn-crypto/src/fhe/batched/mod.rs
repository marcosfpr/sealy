pub mod decryptor;
pub mod encoder;
pub mod encryptor;
pub mod evaluator;

/// Struct to store a batch of elements of the same type.
#[derive(Debug, Clone)]
pub struct Batch<T>(pub Vec<T>);

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

impl<T> Batch<T>
where
	T: Clone,
{
	/// Returns a cloned copy of the element given by the index.
	pub fn get_cloned(&self, index: usize) -> Option<T> {
		self.get(index).cloned()
	}
}

impl<T, E> Batch<Result<T, E>> {
	/// Collects the results in this batch, returning the successful values.
	pub fn collect(self) -> Result<Batch<T>, E> {
		let values = self.0.into_iter().collect::<Result<Vec<_>, _>>()?;
		Ok(Batch(values))
	}
}
