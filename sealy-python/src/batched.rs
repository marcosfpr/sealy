use crate::{
	ciphertext::PyCiphertext,
	context::PyContext,
	keys::{PyPublicKey, PyRelinearizationKey, PySecretKey},
	plaintext::PyPlaintext,
	PyCKKSEvaluator,
};
use pyo3::prelude::*;
use sealy::{Encoder, Evaluator, FromBatchedBytes, SlotCount, ToBatchedBytes};

#[derive(Debug, Clone)]
#[pyclass(name = "PlaintextBatchArray")]
pub struct PyPlaintextBatchArray {
	inner: sealy::Batch<sealy::Plaintext>,
}

#[pymethods]
impl PyPlaintextBatchArray {
	/// Creates a new batch array.
	#[new]
	fn new(ndarr: Vec<PyPlaintext>) -> PyResult<Self> {
		let batch = sealy::Batch(ndarr.iter().map(|x| x.inner.clone()).collect());
		Ok(Self {
			inner: batch,
		})
	}
}

#[derive(Debug, Clone)]
#[pyclass(name = "CiphertextBatchArray")]
pub struct PyCiphertextBatchArray {
	inner: sealy::Batch<sealy::Ciphertext>,
}

#[pymethods]
impl PyCiphertextBatchArray {
	/// Creates a new batch array.
	#[new]
	fn new(ndarr: Vec<PyCiphertext>) -> PyResult<Self> {
		let batch = sealy::Batch(ndarr.iter().map(|x| x.inner.clone()).collect());
		Ok(Self {
			inner: batch,
		})
	}

	/// Converts the batch array to a list of byte arrays.
	pub fn as_batched_bytes(&self) -> PyResult<Vec<Vec<u8>>> {
		let bytes = self.inner.as_batched_bytes().map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to get ciphertext batch as bytes: {:?}",
				e
			))
		})?;
		Ok(bytes)
	}

	/// Creates a new ciphertext batch array from a list of byte arrays.
	#[staticmethod]
	pub fn from_batched_bytes(ctx: &PyContext, bytes: Vec<Vec<u8>>) -> PyResult<Self> {
		let batch = sealy::Batch::from_batched_bytes(&ctx.inner, &bytes).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create ciphertext batch from bytes: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner: batch,
		})
	}
}

/// Encryptor that can encrypt multiple messages at once.
#[pyclass(name = "BatchEncryptor")]
pub struct PyBatchEncryptor {
	inner: sealy::BatchEncryptor<sealy::Asym>,
}

#[pymethods]
impl PyBatchEncryptor {
	/// Creates a new BatchEncryptor instance with a public key.
	#[new]
	fn new(ctx: &PyContext, pk: &PyPublicKey) -> PyResult<Self> {
		let ctx = &ctx.inner;
		let pk = &pk.inner;
		let inner = sealy::BatchEncryptor::with_public_key(ctx, pk).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create BatchEncryptor: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner,
		})
	}

	/// Encrypts a plaintext with the public key and returns the ciphertext as
	/// a serializable object.
	pub fn encrypt(&self, plaintext: PyPlaintextBatchArray) -> PyResult<PyCiphertextBatchArray> {
		let ciphertext = self.inner.encrypt(&plaintext.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encrypt batch: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: ciphertext,
		})
	}
}

/// Decrypts batches of ciphertexts.
#[pyclass(name = "BatchDecryptor")]
pub struct PyBatchDecryptor {
	inner: sealy::BatchDecryptor,
}

#[pymethods]
impl PyBatchDecryptor {
	/// Creates a new batch decryptor.
	#[new]
	pub fn new(ctx: &PyContext, secret_key: &PySecretKey) -> PyResult<Self> {
		let inner = sealy::BatchDecryptor::new(&ctx.inner, &secret_key.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create BatchDecryptor: {:?}",
				e
			))
		})?;
		Ok(Self {
			inner,
		})
	}

	/// Decrypts a ciphertext and returns the plaintext.
	pub fn decrypt(
		&self, ciphertext_batch: &PyCiphertextBatchArray,
	) -> PyResult<PyPlaintextBatchArray> {
		let plaintext = self.inner.decrypt(&ciphertext_batch.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decrypt batch: {:?}",
				e
			))
		})?;
		Ok(PyPlaintextBatchArray {
			inner: plaintext,
		})
	}
}

/// An encoder that encodes data in batches.
#[derive(Clone)]
#[pyclass(name = "CKKSBatchEncoder")]
pub struct PyCKKSBatchEncoder {
	inner: sealy::BatchEncoder<f64, sealy::CKKSEncoder>,
}

#[pymethods]
impl PyCKKSBatchEncoder {
	/// Creates a new BatchEncoder.
	#[new]
	fn new(ctx: &PyContext, scale: f64) -> PyResult<Self> {
		let encoder = sealy::CKKSEncoder::new(&ctx.inner, scale).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to create CKKSEncoder: {:?}",
				e
			))
		})?;
		let inner = sealy::BatchEncoder::new(encoder);
		Ok(Self {
			inner,
		})
	}

	/// Returns the number of slots in this encoder produces.
	fn get_slot_count(&self) -> usize {
		self.inner.get_slot_count()
	}

	/// Encodes the given data into a plaintext.
	///
	/// # Arguments
	/// * `data` - The data to encode.
	///
	/// # Returns
	/// The encoded plaintext.
	fn encode(&self, data: Vec<f64>) -> PyResult<PyPlaintextBatchArray> {
		let batch = self.inner.encode(&data).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to encode batch: {:?}",
				e
			))
		})?;
		Ok(PyPlaintextBatchArray {
			inner: batch,
		})
	}

	/// Decodes the given plaintext into data.
	///
	/// # Arguments
	/// * `batch` - The encoded data.
	///
	/// # Returns
	/// The decoded data.
	fn decode(&self, batch: PyPlaintextBatchArray) -> PyResult<Vec<f64>> {
		let data = self.inner.decode(&batch.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to decode batch: {:?}",
				e
			))
		})?;

		Ok(data)
	}
}

// An evaluator that evaluates batches of data.
#[pyclass(name = "CKKSBatchEvaluator")]
pub struct PyCKKSBatchEvaluator {
	inner: sealy::BatchEvaluator<sealy::CKKSEvaluator>,
}

#[pymethods]
impl PyCKKSBatchEvaluator {
	/// Creates a new BatchEvaluator.
	#[new]
	fn new(ctx: &PyContext) -> PyResult<Self> {
		let evaluator = PyCKKSEvaluator::new(ctx)?;

		let inner = sealy::BatchEvaluator::new(evaluator.inner);

		Ok(Self {
			inner,
		})
	}

	/// Negates a batch of ciphertexts.
	pub fn negate(&self, a: &PyCiphertextBatchArray) -> PyResult<PyCiphertextBatchArray> {
		let negated = self.inner.negate(&a.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to negate batch: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: negated,
		})
	}

	/// Adds two ciphertexts.
	pub fn add(
		&self, a: &PyCiphertextBatchArray, b: &PyCiphertextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let sum = self.inner.add(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to add ciphertexts: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: sum,
		})
	}

	/// Adds many ciphertexts.
	pub fn add_many(&self, a: Vec<PyCiphertextBatchArray>) -> PyResult<PyCiphertextBatchArray> {
		let mut ciphertexts = Vec::new();
		for c in a {
			ciphertexts.push(c.inner);
		}
		let sum = self.inner.add_many(&ciphertexts).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to add many ciphertexts: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: sum,
		})
	}

	/// Multiplies two ciphertexts.
	pub fn multiply(
		&self, a: &PyCiphertextBatchArray, b: &PyCiphertextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let product = self.inner.multiply(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to multiply ciphertexts: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: product,
		})
	}

	/// Multiplies many ciphertexts.
	pub fn multiply_many(
		&self, a: Vec<PyCiphertextBatchArray>, relin_keys: &PyRelinearizationKey,
	) -> PyResult<PyCiphertextBatchArray> {
		let mut ciphertexts = Vec::new();
		for c in a {
			ciphertexts.push(c.inner);
		}
		let product = self
			.inner
			.multiply_many(&ciphertexts, &relin_keys.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to multiply many ciphertexts: {:?}",
					e
				))
			})?;
		Ok(PyCiphertextBatchArray {
			inner: product,
		})
	}

	/// Subtracts two ciphertexts.
	pub fn sub(
		&self, a: &PyCiphertextBatchArray, b: &PyCiphertextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let difference = self.inner.sub(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to subtract ciphertexts: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: difference,
		})
	}

	/// Adds a ciphertext and a plaintext.
	pub fn add_plain(
		&self, a: &PyCiphertextBatchArray, b: &PyPlaintextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let sum = self.inner.add_plain(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to add plaintext to ciphertext: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: sum,
		})
	}

	/// Subtracts a plaintext from a ciphertext.
	pub fn sub_plain(
		&self, a: &PyCiphertextBatchArray, b: &PyPlaintextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let difference = self.inner.sub_plain(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to subtract plaintext from ciphertext: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: difference,
		})
	}

	/// Multiplies a ciphertext by a plaintext.
	pub fn multiply_plain(
		&self, a: &PyCiphertextBatchArray, b: &PyPlaintextBatchArray,
	) -> PyResult<PyCiphertextBatchArray> {
		let product = self.inner.multiply_plain(&a.inner, &b.inner).map_err(|e| {
			PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
				"Failed to multiply ciphertext by plaintext: {:?}",
				e
			))
		})?;
		Ok(PyCiphertextBatchArray {
			inner: product,
		})
	}

	pub fn relinearize(
		&self, a: &PyCiphertextBatchArray, relin_keys: &PyRelinearizationKey,
	) -> PyResult<PyCiphertextBatchArray> {
		let relinearized = self
			.inner
			.relinearize(&a.inner, &relin_keys.inner)
			.map_err(|e| {
				PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
					"Failed to relinearize ciphertext: {:?}",
					e
				))
			})?;
		Ok(PyCiphertextBatchArray {
			inner: relinearized,
		})
	}
}
