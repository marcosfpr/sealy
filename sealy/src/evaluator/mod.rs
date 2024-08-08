use crate::error::*;
use crate::{GaloisKey, RelinearizationKey};

pub mod base;
pub mod bfv;
pub mod ckks;

/// An interface for an evaluator.
pub trait Evaluator {
	/// The plaintext type.
	/// This is the type of the plaintext that the evaluator can operate on.
	type Plaintext;

	/// The ciphertext type.
	/// This is the type of the ciphertext that the evaluator can operate on.
	type Ciphertext;

	/// Negates a ciphertext inplace.
	///   * `a` - the value to negate
	fn negate_inplace(
		&self,
		a: &mut Self::Ciphertext,
	) -> Result<()>;

	/// Negates a ciphertext into a new ciphertext.
	///   * `a` - the value to negate
	fn negate(
		&self,
		a: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Add `a` and `b` and store the result in `a`.
	///  * `a` - the accumulator
	///  * `b` - the added value
	fn add_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<()>;

	/// Adds `a` and `b`.
	///  * `a` - first operand
	///  * `b` - second operand
	fn add(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Performs an addition reduction of multiple ciphertexts packed into a slice.
	///  * `a` - a slice of ciphertexts to sum.
	fn add_many(
		&self,
		a: &[Self::Ciphertext],
	) -> Result<Self::Ciphertext>;

	/// Performs an multiplication reduction of multiple ciphertexts packed into a slice. This
	///  method creates a tree of multiplications with relinearization after each operation.
	///  * `a` - a slice of ciphertexts to sum.
	///  * `relin_keys` - the relinearization keys.
	fn multiply_many(
		&self,
		a: &[Self::Ciphertext],
		relin_keys: &RelinearizationKey,
	) -> Result<Self::Ciphertext>;

	/// Subtracts `b` from `a` and stores the result in `a`.
	///  * `a` - the left operand and destination
	///  * `b` - the right operand
	fn sub_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<()>;

	/// Subtracts `b` from `a`.
	///  * `a` - the left operand
	///  * `b` - the right operand
	fn sub(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Multiplies `a` and `b` and stores the result in `a`.
	///  * `a` - the left operand and destination.
	///  * `b` - the right operand.
	fn multiply_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<()>;

	/// Multiplies `a` and `b`.
	///  * `a` - the left operand.
	///  * `b` - the right operand.
	fn multiply(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Squares `a` and stores the result in `a`.
	///  * `a` - the value to square.
	fn square_inplace(
		&self,
		a: &mut Self::Ciphertext,
	) -> Result<()>;

	/// Squares `a`.
	///  * `a` - the value to square.
	fn square(
		&self,
		a: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and
	/// stores the result in the destination parameter.
	///
	/// # Remarks
	/// In the BFV scheme if you've set up a coefficient modulus chain, this reduces the
	/// number of bits needed to represent the ciphertext. This in turn speeds up operations.
	///
	/// If you haven't set up a modulus chain, don't use this.
	///
	/// TODO: what does this mean for CKKS?
	fn mod_switch_to_next(
		&self,
		a: &Self::Ciphertext,
	) -> Result<Self::Ciphertext>;

	/// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus down to q_1...q_{k-1} and
	/// stores the result in the destination parameter. This does function does so in-place.
	///
	/// # Remarks
	/// In the BFV scheme if you've set up a coefficient modulus chain, this reduces the
	/// number of bits needed to represent the ciphertext. This in turn speeds up operations.
	///
	/// If you haven't set up a modulus chain, don't use this.
	///
	/// TODO: what does this mean for CKKS?
	fn mod_switch_to_next_inplace(
		&self,
		a: &Self::Ciphertext,
	) -> Result<()>;

	/// Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1}.
	fn mod_switch_to_next_plaintext(
		&self,
		a: &Self::Plaintext,
	) -> Result<Self::Plaintext>;

	/// Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo q_1...q_{k-1}.
	/// This variant does so in-place.
	fn mod_switch_to_next_inplace_plaintext(
		&self,
		a: &Self::Plaintext,
	) -> Result<()>;

	/// This functions raises encrypted to a power and stores the result in the destination parameter. Dynamic
	/// memory allocations in the process are allocated from the memory pool pointed to by the given
	/// MemoryPoolHandle. The exponentiation is done in a depth-optimal order, and relinearization is performed
	/// automatically after every multiplication in the process. In relinearization the given relinearization keys
	/// are used.
	fn exponentiate(
		&self,
		a: &Self::Ciphertext,
		exponent: u64,
		relin_keys: &RelinearizationKey,
	) -> Result<Self::Ciphertext>;

	/// This functions raises encrypted to a power and stores the result in the destination parameter. Dynamic
	/// memory allocations in the process are allocated from the memory pool pointed to by the given
	/// MemoryPoolHandle. The exponentiation is done in a depth-optimal order, and relinearization is performed
	/// automatically after every multiplication in the process. In relinearization the given relinearization keys
	/// are used.
	fn exponentiate_inplace(
		&self,
		a: &Self::Ciphertext,
		exponent: u64,
		relin_keys: &RelinearizationKey,
	) -> Result<()>;

	/// Adds a ciphertext and a plaintext.
	/// * `a` - the ciphertext
	/// * `b` - the plaintext
	fn add_plain(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<Self::Ciphertext>;

	/// Adds a ciphertext and a plaintext.
	/// * `a` - the ciphertext
	/// * `b` - the plaintext
	fn add_plain_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<()>;

	/// Subtract a plaintext from a ciphertext.
	/// * `a` - the ciphertext
	/// * `b` - the plaintext
	fn sub_plain(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<Self::Ciphertext>;

	/// Subtract a plaintext from a ciphertext and store the result in the ciphertext.
	///  * `a` - the ciphertext
	///  * `b` - the plaintext
	fn sub_plain_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<()>;

	/// Multiply a ciphertext by a plaintext.
	///  * `a` - the ciphertext
	///  * `b` - the plaintext
	fn multiply_plain(
		&self,
		a: &Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<Self::Ciphertext>;

	/// Multiply a ciphertext by a plaintext and store in the ciphertext.
	///  * `a` - the ciphertext
	///  * `b` - the plaintext
	fn multiply_plain_inplace(
		&self,
		a: &mut Self::Ciphertext,
		b: &Self::Plaintext,
	) -> Result<()>;

	/// This functions relinearizes a ciphertext in-place, reducing it to 2 polynomials. This
	/// reduces future noise growth under multiplication operations.
	fn relinearize_inplace(
		&self,
		a: &mut Self::Ciphertext,
		relin_keys: &RelinearizationKey,
	) -> Result<()>;

	/// This functions relinearizes a ciphertext, reducing it to 2 polynomials. This
	/// reduces future noise growth under multiplication operations.
	fn relinearize(
		&self,
		a: &Self::Ciphertext,
		relin_keys: &RelinearizationKey,
	) -> Result<Self::Ciphertext>;

	/// Rotates plaintext matrix rows cyclically.
	///
	/// When batching is used with the BFV scheme, this function rotates the encrypted plaintext matrix rows
	/// cyclically to the left (steps > 0) or to the right (steps < 0). Since the size of the batched matrix
	/// is 2-by-(N/2), where N is the degree of the polynomial modulus, the number of steps to rotate must have
	/// absolute value at most N/2-1.
	///
	/// * `a` - The ciphertext to rotate
	/// * `steps` - The number of steps to rotate (positive left, negative right)
	/// * `galois_keys` - The Galois keys
	fn rotate_rows(
		&self,
		a: &Self::Ciphertext,
		steps: i32,
		galois_keys: &GaloisKey,
	) -> Result<Self::Ciphertext>;

	/// Rotates plaintext matrix rows cyclically. This variant does so in-place
	///
	/// When batching is used with the BFV scheme, this function rotates the encrypted plaintext matrix rows
	/// cyclically to the left (steps &gt; 0) or to the right (steps &lt; 0). Since the size of the batched matrix
	/// is 2-by-(N/2), where N is the degree of the polynomial modulus, the number of steps to rotate must have
	/// absolute value at most N/2-1.
	///
	/// * `a` - The ciphertext to rotate
	/// * `steps` - The number of steps to rotate (positive left, negative right)
	/// * `galois_keys` - The Galois keys
	fn rotate_rows_inplace(
		&self,
		a: &Self::Ciphertext,
		steps: i32,
		galois_keys: &GaloisKey,
	) -> Result<()>;

	/// Rotates plaintext matrix columns cyclically.
	///
	/// When batching is used with the BFV scheme, this function rotates the encrypted plaintext matrix columns
	/// cyclically. Since the size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial
	/// modulus, this means simply swapping the two rows. Dynamic memory allocations in the process are allocated
	/// from the memory pool pointed to by the given MemoryPoolHandle.
	///
	/// * `encrypted` - The ciphertext to rotate
	/// * `galoisKeys` - The Galois keys
	fn rotate_columns(
		&self,
		a: &Self::Ciphertext,
		galois_keys: &GaloisKey,
	) -> Result<Self::Ciphertext>;

	/// Rotates plaintext matrix columns cyclically. This variant does so in-place.
	///
	/// When batching is used with the BFV scheme, this function rotates the encrypted plaintext matrix columns
	/// cyclically. Since the size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial
	/// modulus, this means simply swapping the two rows. Dynamic memory allocations in the process are allocated
	/// from the memory pool pointed to by the given MemoryPoolHandle.
	///
	/// * `encrypted` - The ciphertext to rotate
	/// * `galoisKeys` - The Galois keys
	fn rotate_columns_inplace(
		&self,
		a: &Self::Ciphertext,
		galois_keys: &GaloisKey,
	) -> Result<()>;
}
