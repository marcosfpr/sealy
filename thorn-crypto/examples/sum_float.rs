use thorn_seal::{
	CKKSEncoder, CkksEncryptionParametersBuilder, CoefficientModulus, Context,
	EncryptionParameters, KeyGenerator, SecurityLevel,
};

fn main() -> anyhow::Result<()> {
	// generate keypair to encrypt and decrypt data.
	let degree = 8192;
	let security_level = SecurityLevel::TC128;
	let bit_sizes = [60, 40, 40, 60];

	let expand_mod_chain = false;
	let modulus_chain = CoefficientModulus::create(degree, bit_sizes.as_slice())?;
	let encryption_parameters: EncryptionParameters = CkksEncryptionParametersBuilder::new()
		.set_poly_modulus_degree(degree)
		.set_coefficient_modulus(modulus_chain)
		.build()?;

	let ctx = Context::new(&encryption_parameters, expand_mod_chain, security_level)?;

	println!("Context error: {:?}", ctx.get_parameter_error_message());

	let key_gen = KeyGenerator::new(&ctx)?;
	let encoder = CKKSEncoder::new(&ctx)?;

	// let public_key = key_gen.create_public_key();
	// let private_key = key_gen.secret_key();

	// let encryptor = Encryptor::with_public_and_secret_key(&ctx, &public_key, &private_key)?;
	// let decryptor = Decryptor::new(&ctx, &private_key)?;

	// let evaluator = CKKSEvaluator::new(&ctx)?;

	// let x = 5.2;
	// let y = 10.333;

	// // scale = pow(2, 30)
	// let scale = 2.0f64.powi(30);

	// let x_enc = encryptor.encrypt(&encoder.encode(&[x], scale)?)?;
	// let y_enc = encryptor.encrypt(&encoder.encode(&[y], scale)?)?;

	// println!("Summing x + y...");
	// println!("x: {:#?}", x_enc);
	// println!("y: {:#?}", y_enc);

	// let sum = evaluator.add(&x_enc, &y_enc)?;
	// let sum_dec = decryptor.decrypt(&sum)?;

	// let sum_dec = encoder.decode(&sum_dec)?;

	// println!("Sum: {:?}", sum_dec.first());

	Ok(())
}
