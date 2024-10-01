from sealy import (CKKSEncoder, CkksEncryptionParametersBuilder,
                   CoefficientModulus, Context, DegreeType, SecurityLevel)


def test_can_create_and_drop_ckks_encoder():
    params = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [60, 40, 40, 60])
        )
        .build()
    )
    scale = 2.0**40

    ctx = Context(params, False, SecurityLevel(128))
    encoder = CKKSEncoder(ctx, scale)
    del encoder


def test_can_get_slots_ckks_encoder():
    params = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [60, 40, 40, 60])
        )
        .build()
    )
    scale = 2.0**40

    ctx = Context(params, False, SecurityLevel(128))
    encoder = CKKSEncoder(ctx, scale)

    assert encoder.get_slot_count() == 4096


def test_can_get_encode_and_decode_float():
    params = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [60, 40, 40, 60])
        )
        .build()
    )
    scale = 2.0**40

    ctx = Context(params, False, SecurityLevel(128))
    encoder = CKKSEncoder(ctx, scale)

    data = [i / 10 for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_float(data)
    data_2 = encoder.decode_float(plaintext)

    # assert float array with 1e-6 precision
    assert all(abs(a - b) < 1e-6 for a, b in zip(data, data_2))
