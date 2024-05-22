//! Allows the encoding of large tensors and perform homomorphic operations on them.

use crate::Plaintext;

pub mod encoder;

/// A tensor of plaintexts.
#[derive(Debug)]
pub struct PlaintextTensor {
	data: Vec<Plaintext>,
	shape: Vec<usize>,
}

impl PlaintextTensor {
	/// Creates a new tensor with the given data and shape.
	pub fn new(data: Vec<Plaintext>, shape: Vec<usize>) -> Self {
		Self {
			data,
			shape,
		}
	}

	/// Returns the data of the tensor.
	pub fn data(&self) -> &Vec<Plaintext> {
		&self.data
	}

	/// Returns the shape of the tensor.
	pub fn shape(&self) -> &Vec<usize> {
		&self.shape
	}
}
