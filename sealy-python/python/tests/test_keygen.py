import json

from sealy import (BfvEncryptionParametersBuilder, CoefficientModulus, Context,
                   DegreeType, KeyGenerator, PlainModulus, SecurityLevel)


def test_can_create_secret_key():
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

    secret_key = gen.secret_key()

    gen_2 = KeyGenerator(ctx)
    secret_key_2 = gen_2.secret_key()

    assert secret_key_2.as_bytes() != secret_key.as_bytes()


def test_can_create_public_key():
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

    gen.create_public_key()


def test_can_create_relin_key():
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

    gen.create_relinearization_key()


def test_can_create_galois_key():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.bfv(DegreeType(8192), SecurityLevel(128))
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 32))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    gen = KeyGenerator(ctx)

    gen.create_galois_key()


def test_can_init_from_existing_secret_key():
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

    secret_key = gen.secret_key()

    gen_2 = KeyGenerator.from_secret_key(ctx, secret_key)
    secret_key_2 = gen_2.secret_key()

    assert secret_key_2.as_bytes() == secret_key.as_bytes()
