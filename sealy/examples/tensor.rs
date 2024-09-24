use rand::Rng;
use sealy::{
	CKKSEncoder, CKKSEncryptionParametersBuilder, Ciphertext, CoefficientModulusFactory, Context,
	DegreeType, EncryptionParameters, Error, Evaluator, KeyGenerator, SecurityLevel, Tensor,
	TensorDecryptor, TensorEncoder, TensorEncryptor, TensorEvaluator,
};

fn generate_random_tensor(size: usize) -> Vec<f64> {
	let mut rng = rand::thread_rng();
	let mut tensor = Vec::with_capacity(size);
	for _ in 0..size {
		tensor.push(rng.gen_range(0.0..1.0));
	}
	tensor
}

fn average_ciphertexts(
	ctx: &Context,
	encoder: &TensorEncoder<CKKSEncoder>,
	ciphertexts: &[Tensor<Ciphertext>],
	size: usize,
) -> Result<Tensor<Ciphertext>, Error> {
	let evaluator = TensorEvaluator::ckks(ctx)?;
	let cipher = evaluator.add_many(ciphertexts)?;

	let fraction = 1.0 / ciphertexts.len() as f64;
	let fraction = vec![fraction; size];
	let fraction = encoder.encode_f64(&fraction)?;

	evaluator.multiply_plain(&cipher, &fraction)
}

fn average_plaintexts(plaintexts: &[Vec<f64>]) -> Vec<f64> {
	// average element-wise
	let mut avg = vec![0.0; plaintexts[0].len()];
	for tensor in plaintexts {
		for (i, &val) in tensor.iter().enumerate() {
			avg[i] += val;
		}
	}
	avg.iter_mut()
		.for_each(|val| *val /= plaintexts.len() as f64);
	avg
}

fn main() -> Result<(), Error> {
	// generate keypair to encrypt and decrypt data.
	let degree = DegreeType::D8192;
	let security_level = SecurityLevel::TC128;
	let bit_sizes = [60, 40, 40, 60];

	let expand_mod_chain = false;
	let modulus_chain = CoefficientModulusFactory::build(degree, bit_sizes.as_slice())?;
	let encryption_parameters: EncryptionParameters = CKKSEncryptionParametersBuilder::new()
		.set_poly_modulus_degree(degree)
		.set_coefficient_modulus(modulus_chain.clone())
		.build()?;

	let ctx = Context::new(&encryption_parameters, expand_mod_chain, security_level)?;

	let key_gen = KeyGenerator::new(&ctx)?;

	let encoder = TensorEncoder::new(CKKSEncoder::new(&ctx, 2.0f64.powi(40))?);

	let public_key = key_gen.create_public_key();
	let private_key = key_gen.secret_key();

	let encryptor = TensorEncryptor::with_public_and_secret_key(&ctx, &public_key, &private_key)?;
	let decryptor = TensorDecryptor::new(&ctx, &private_key)?;

	let start = std::time::Instant::now();
	let client_1_gradients = generate_random_tensor(11_000_000);
	let client_2_gradients = generate_random_tensor(11_000_000);
	let client_3_gradients = generate_random_tensor(11_000_000);
	println!("generate time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let client_1_encoded_gradients = encoder.encode_f64(&client_1_gradients)?;
	let client_2_encoded_gradients = encoder.encode_f64(&client_2_gradients)?;
	let client_3_encoded_gradients = encoder.encode_f64(&client_3_gradients)?;
	println!("encode time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let client_1_encrypted_gradients = encryptor.encrypt(&client_1_encoded_gradients)?;
	let client_2_encrypted_gradients = encryptor.encrypt(&client_2_encoded_gradients)?;
	let client_3_encrypted_gradients = encryptor.encrypt(&client_3_encoded_gradients)?;
	println!("encrypt time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let avg_truth =
		average_plaintexts(&[client_1_gradients, client_2_gradients, client_3_gradients]);
	println!("avg plaintext time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let avg = average_ciphertexts(
		&ctx,
		&encoder,
		&[
			client_1_encrypted_gradients,
			client_2_encrypted_gradients,
			client_3_encrypted_gradients,
		],
		10,
	)?;
	println!("avg ciphertext time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let avg_dec = decryptor.decrypt(&avg)?;
	println!("decrypt time: {:?}", start.elapsed());

	let start = std::time::Instant::now();
	let avg_plain = encoder.decode_f64(&avg_dec)?;
	println!("decode time: {:?}", start.elapsed());

	// get the first 10
	let avg_plain = avg_plain.iter().take(10).cloned().collect::<Vec<f64>>();

	// compare avg_truth and avg_plain with a tolerance of 1e-6
	for (t, p) in avg_truth.iter().zip(avg_plain.iter()) {
		assert!((t - p).abs() < 1e-6);
	}

	Ok(())
}
