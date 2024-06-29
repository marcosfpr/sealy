from sealy import (BfvEncryptionParametersBuilder, CoefficientModulus, Context,
                   DegreeType, Encryptor, KeyGenerator, SecurityLevel)


def test_can_create_and_drop_encryptor():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus_constant(1234)
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))

    gen = KeyGenerator(ctx)

    public_key = gen.create_public_key()

    encryptor = Encryptor(ctx, public_key)

    del encryptor
