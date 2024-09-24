use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rand::Rng;
use sealy::{
	CKKSEncoder, CKKSEncryptionParametersBuilder, Ciphertext, CoefficientModulusFactory, Context,
	DegreeType, EncryptionParameters, Error, Evaluator, KeyGenerator, SecurityLevel, Tensor,
	TensorEncoder, TensorEncryptor, TensorEvaluator,
};

fn generate_clients_gradients(
	num_clients: usize,
	tensor_dim: usize,
) -> Vec<Vec<f64>> {
	let mut clients = Vec::with_capacity(num_clients);
	for _ in 0..num_clients {
		let mut tensor = Vec::with_capacity(tensor_dim);
		for _ in 0..tensor_dim {
			tensor.push(rand::thread_rng().gen_range(0.0..1.0));
		}
		clients.push(tensor);
	}
	clients
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

fn aggregate(
	ctx: &Context,
	encoder: &TensorEncoder<CKKSEncoder>,
	ciphertexts: &[Tensor<Ciphertext>],
	dimension: usize,
) -> Result<Tensor<Ciphertext>, Error> {
	let batch_evaluator = TensorEvaluator::ckks(ctx)?;

	let cipher = batch_evaluator.add_many(ciphertexts)?;

	let fraction = 1.0 / ciphertexts.len() as f64;
	let fraction = vec![fraction; dimension];
	let fraction = encoder.encode_f64(&fraction)?;

	batch_evaluator.multiply_plain(&cipher, &fraction)
}

fn run_benchmark(
	c: &mut Criterion,
	dimension: usize,
	num_clients: usize,
) {
	println!("dimension: {}", dimension);
	println!("num_clients: {}", num_clients);

	print!("Generating clients gradients...");
	let clients = generate_clients_gradients(num_clients, dimension);
	println!("done");

	print!("Creating CKKS context...");
	let ctx = create_ckks_context(DegreeType::D32768, &[60, 40, 40, 60])
		.expect("Failed to create CKKS context");
	println!("done");

	let key_gen = KeyGenerator::new(&ctx).expect("Failed to create key generator");
	let scale = 2.0f64.powi(40);
	let encoder = CKKSEncoder::new(&ctx, scale).expect("Failed to create encoder");
	let batch_encoder = TensorEncoder::new(encoder);

	let public_key = key_gen.create_public_key();
	let private_key = key_gen.secret_key();

	println!("Encoding clients gradients...");
	let mut plaintexts = Vec::with_capacity(num_clients);
	for client in clients.iter() {
		let encoded = batch_encoder
			.encode_f64(client)
			.expect("Failed to encode client gradients");
		plaintexts.push(encoded);
	}

	println!("Encrypting clients gradients...");
	let mut ciphertexts = Vec::with_capacity(num_clients);
	let encryptor = TensorEncryptor::with_public_and_secret_key(&ctx, &public_key, &private_key)
		.expect("Failed to create encryptor");
	for plaintext in plaintexts.iter() {
		let ciphertext = encryptor
			.encrypt(plaintext)
			.expect("Failed to encrypt client gradients");
		ciphertexts.push(ciphertext);
	}

	let benchmark_name = format!(
		"aggregate CKKS (num_clients={}, dimension={})",
		num_clients, dimension
	);
	println!("Running benchmark: {}", benchmark_name);
	c.bench_function(&benchmark_name, |b| {
		b.iter(|| {
			aggregate(
				black_box(&ctx),
				black_box(&batch_encoder),
				black_box(&ciphertexts),
				black_box(dimension),
			)
		})
	});
}

fn criterion_benchmark(c: &mut Criterion) {
	let dimensions = [10_000, 50_000, 100_000, 500_000, 1_000_000];
	let clients = [5, 25, 50, 100];

	for dimension in dimensions.iter() {
		for num_clients in clients.iter() {
			run_benchmark(c, *dimension, *num_clients);
		}
	}
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
