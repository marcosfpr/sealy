use rand::Rng;
use sealy::{
	CKKSEncoder, CKKSEncryptionParametersBuilder, CoefficientModulusFactory, Context, DegreeType,
	EncryptionParameters, Error, KeyGenerator, SecurityLevel, TensorDecryptor, TensorEncoder,
	TensorEncryptor,
};

fn generate_random_tensor(size: usize) -> Vec<f64> {
	let mut rng = rand::thread_rng();
	let mut tensor = Vec::with_capacity(size);
	for _ in 0..size {
		tensor.push(rng.gen_range(0.0..1.0));
	}
	tensor
}

fn create_ckks_context(
	degree: DegreeType,
	bit_sizes: &[i32],
) -> Result<Context, Error> {
	let security_level = SecurityLevel::TC128;
	let expand_mod_chain = false;
	let modulus_chain = CoefficientModulusFactory::build(degree, bit_sizes)?;
	let encryption_parameters: EncryptionParameters = CKKSEncryptionParametersBuilder::new()
		.set_poly_modulus_degree(degree)
		.set_coefficient_modulus(modulus_chain.clone())
		.build()?;

	let ctx = Context::new(&encryption_parameters, expand_mod_chain, security_level)?;

	Ok(ctx)
}

fn main() -> Result<(), Error> {
	let ctx = create_ckks_context(DegreeType::D8192, &[60, 40, 40, 60])?;

	let key_gen = KeyGenerator::new(&ctx)?;

	let encoder = TensorEncoder::new(CKKSEncoder::new(&ctx, 2.0f64.powi(40))?);

	let public_key = key_gen.create_public_key();
	let private_key = key_gen.secret_key();

	let encryptor = TensorEncryptor::with_public_and_secret_key(&ctx, &public_key, &private_key)?;
	let decryptor = TensorDecryptor::new(&ctx, &private_key)?;

	let dim = 8_000_000;
	let tensor = generate_random_tensor(dim);

	let rounds = 10;
	let delay = std::time::Duration::from_secs(60);

	for i in 0..rounds {
		println!("Start Round: {}", i);
		println!("Encoding tensor...");
		let encoded = encoder.encode_f64(&tensor)?;
		println!("Encrypting tensor...");
		let encrypted = encryptor.encrypt(&encoded)?;
		println!("Decrypting tensor...");
		let decrypted = decryptor.decrypt(&encrypted)?;
		println!("Decoding tensor...");
		let decoded = encoder.decode_f64(&decrypted)?;
		std::mem::drop(decoded);
		println!("==================");
		std::thread::sleep(delay);
	}

	Ok(())
}
