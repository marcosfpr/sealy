from sealy import (BFVEncoder, BfvEncryptionParametersBuilder,
                   CoefficientModulus, Context, DegreeType, PlainModulus,
                   SecurityLevel)


def test_can_create_and_drop_bfv_encoder():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)
    del encoder


def test_can_get_slots_bfv_encoder():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)

    assert encoder.get_slot_count() == 8192


def test_can_get_encode_and_decode_unsigned():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)

    data = [i for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_int(data)
    data_2 = encoder.decode_int(plaintext)

    assert data == data_2


def test_can_get_encode_and_decode_signed():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)

    data = [i for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_int(data)
    data_2 = encoder.decode_int(plaintext)

    assert data == data_2


def test_scalar_encoder_can_encode_decode_signed():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)

    p = encoder.encode_int([-15])

    assert encoder.decode_int(p)[0] == -15


def test_scalar_encoder_can_encode_decode_unsigned():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    encoder = BFVEncoder(ctx)

    p = encoder.encode_int([42])

    assert encoder.decode_int(p)[0] == 42
