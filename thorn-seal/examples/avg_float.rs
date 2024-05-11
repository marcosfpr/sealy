use rand::Rng;
use thorn_seal::{
	CKKSEncoder, CKKSEvaluator, Ciphertext, CkksEncryptionParametersBuilder, CoefficientModulus,
	Context, Decryptor, EncryptionParameters, Encryptor, Error, Evaluator, KeyGenerator,
	SecurityLevel,
};

fn generate_random_tensor(size: usize) -> Vec<f64> {
	let mut rng = rand::thread_rng();
	let mut tensor = Vec::with_capacity(size);
	for _ in 0..size {
		tensor.push(rng.gen_range(0.0..1.0));
	}
	tensor
}

fn create_ckks_context(degree: u64, bit_sizes: &[i32]) -> Result<Context, Error> {
	let security_level = SecurityLevel::TC128;
	let expand_mod_chain = false;
	let modulus_chain = CoefficientModulus::create(degree, bit_sizes)?;
	let encryption_parameters: EncryptionParameters = CkksEncryptionParametersBuilder::new()
		.set_poly_modulus_degree(degree)
		.set_coefficient_modulus(modulus_chain.clone())
		.build()?;

	let ctx = Context::new(&encryption_parameters, expand_mod_chain, security_level)?;

	Ok(ctx)
}

fn average_ciphertexts(
	ctx: &Context,
	encoder: &CKKSEncoder,
	ciphertexts: &[Ciphertext],
	size: usize,
	scale: f64,
) -> Result<Ciphertext, Error> {
	let evaluator = CKKSEvaluator::new(ctx)?;
	let cipher = evaluator.add_many(ciphertexts)?;

	let fraction = 1.0 / ciphertexts.len() as f64;
	let fraction = vec![fraction; size];
	let fraction = encoder.encode(&fraction, ctx, scale)?;

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

/// Average simulating the averaging of gradients of 3 clients in a federated learning setting
fn main() -> Result<(), Error> {
	let ctx = create_ckks_context(8192, &[60, 40, 40, 60])?;

	let key_gen = KeyGenerator::new(&ctx)?;
	let encoder = CKKSEncoder::new(&ctx)?;
	let scale = 2.0f64.powi(40);

	let public_key = key_gen.create_public_key();
	let private_key = key_gen.secret_key();

	let client_1_gradients = generate_random_tensor(10);
	let client_2_gradients = generate_random_tensor(10);
	let client_3_gradients = generate_random_tensor(10);

	println!("client_1_gradients: {:?}", client_1_gradients);
	println!("client_2_gradients: {:?}", client_2_gradients);
	println!("client_3_gradients: {:?}", client_3_gradients);

	let client_1_encoded_gradients = encoder.encode(&client_1_gradients, &ctx, scale)?;
	let client_2_encoded_gradients = encoder.encode(&client_2_gradients, &ctx, scale)?;
	let client_3_encoded_gradients = encoder.encode(&client_3_gradients, &ctx, scale)?;

	println!(
		"client_1_encoded_gradients: {:?}",
		client_1_encoded_gradients
	);
	println!(
		"client_2_encoded_gradients: {:?}",
		client_2_encoded_gradients
	);
	println!(
		"client_3_encoded_gradients: {:?}",
		client_3_encoded_gradients
	);

	let encryptor = Encryptor::with_public_and_secret_key(&ctx, &public_key, &private_key)?;
	let decryptor = Decryptor::new(&ctx, &private_key)?;

	let client_1_encrypted_gradients = encryptor.encrypt(&client_1_encoded_gradients)?;
	let client_2_encrypted_gradients = encryptor.encrypt(&client_2_encoded_gradients)?;
	let client_3_encrypted_gradients = encryptor.encrypt(&client_3_encoded_gradients)?;

	println!(
		"client_1_encrypted_gradients: {:#?}",
		client_1_encrypted_gradients
	);

	println!(
		"client_2_encrypted_gradients: {:#?}",
		client_2_encrypted_gradients
	);

	println!(
		"client_3_encrypted_gradients: {:#?}",
		client_3_encrypted_gradients
	);

	println!("Averaging gradients...");
	println!(
		"plaintext average: {:?}",
		average_plaintexts(&[client_1_gradients, client_2_gradients, client_3_gradients])
	);

	let avg = average_ciphertexts(
		&ctx,
		&encoder,
		&[
			client_1_encrypted_gradients,
			client_2_encrypted_gradients,
			client_3_encrypted_gradients,
		],
		10,
		scale,
	)?;

	println!("ciphertext average: {:?}", avg);

	let avg_dec = decryptor.decrypt(&avg)?;
	let avg_plain = encoder.decode(&avg_dec)?;

	// get the first 10
	let avg_plain = avg_plain.iter().take(10).cloned().collect::<Vec<f64>>();
	println!("decrypted average: {:?}", avg_plain);

	Ok(())
}