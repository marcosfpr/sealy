from sealy import (BfvEncryptionParametersBuilder, Ciphertext,
                   CoefficientModulus, Context, DegreeType, PolynomialArray,
                   SecurityLevel)
from sealy.sealy import BFVEncoder, Encryptor, KeyGenerator, PlainModulus


def test_can_create_and_destroy_static_polynomial_array():
    poly_array = PolynomialArray()
    del poly_array


def test_can_create_polynomial_from_ciphertext():
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
    ciphertext = Ciphertext()
    poly_array = PolynomialArray.from_ciphertext(ctx, ciphertext)

    assert poly_array.is_reserved()


def test_polynomial_array_initially_not_reserved():
    poly_array = PolynomialArray()
    assert not poly_array.is_reserved()


def generate_ciphertext_example():
    coeff_modulus = CoefficientModulus.create(
        DegreeType(8192), [50, 30, 30, 50, 50]
    )
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coefficient_modulus(coeff_modulus)
        .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 20))
        .build()
    )

    ctx = Context(params, False, SecurityLevel(128))
    gen = KeyGenerator(ctx)

    encoder = BFVEncoder(ctx)

    data = [i for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_int(data)

    public_key = gen.create_public_key()
    secret_key = gen.secret_key()

    encryptor = Encryptor(ctx, public_key)

    ciphertext, components = encryptor.encrypt_return_components(plaintext)

    return (
        ctx,
        coeff_modulus,
        public_key,
        ciphertext,
        components.get_u(),
        components.get_e(),
        components.get_r(),
    )


def test_correct_poly_array_sizes_from_ciphertext():
    ctx, _, public_key, ciphertext, u, e, r = generate_ciphertext_example()
    poly_array_public_key = PolynomialArray.from_public_key(ctx, public_key)
    poly_array_ciphertext = PolynomialArray.from_ciphertext(ctx, ciphertext)

    poly_array_ciphertext_encoded = poly_array_ciphertext.as_ints()
    poly_array_public_key_encoded = poly_array_public_key.as_ints()
    u_encoded = u.as_ints()
    e_encoded = e.as_ints()

    assert poly_array_public_key.is_reserved()
    assert poly_array_ciphertext.is_reserved()
    assert u.is_reserved()
    assert e.is_reserved()

    # Ciphertext size checks
    assert (
        poly_array_ciphertext.get_num_polynomials()
        == ciphertext.get_num_polynomials()
    )
    assert poly_array_ciphertext.get_poly_modulus_degree() == 8192
    assert (
        poly_array_ciphertext.get_coeff_modulus_size()
        == ciphertext.get_coeff_modulus_size()
    )

    assert (
        len(poly_array_ciphertext_encoded)
        == poly_array_ciphertext.get_num_polynomials()
        * poly_array_ciphertext.get_poly_modulus_degree()
        * poly_array_ciphertext.get_coeff_modulus_size()
    )

    # Public key
    assert poly_array_public_key.get_num_polynomials() == 2
    assert poly_array_public_key.get_poly_modulus_degree() == 8192
    assert poly_array_public_key.get_coeff_modulus_size() == 4

    assert (
        len(poly_array_public_key_encoded)
        == poly_array_public_key.get_num_polynomials()
        * poly_array_public_key.get_poly_modulus_degree()
        * poly_array_public_key.get_coeff_modulus_size()
    )

    # u
    assert u.get_num_polynomials() == 1
    assert u.get_poly_modulus_degree() == 8192
    assert u.get_coeff_modulus_size() == 4
    assert (
        len(u_encoded)
        == poly_array_public_key.get_poly_modulus_degree()
        * poly_array_ciphertext.get_coeff_modulus_size()
    )

    # e
    assert e.get_num_polynomials() == 2
    assert e.get_poly_modulus_degree() == 8192
    assert e.get_coeff_modulus_size() == 4
    assert (
        len(e_encoded)
        == ciphertext.get_num_polynomials()
        * poly_array_public_key.get_poly_modulus_degree()
        * ciphertext.get_coeff_modulus_size()
    )

    # r
    assert r.size() == 8192


def test_multiprecision_and_back_is_identity():
    ctx, _, _, ciphertext, _, _, _ = generate_ciphertext_example()
    poly_array = PolynomialArray.from_ciphertext(ctx, ciphertext)

    poly_array_encoded_original = poly_array.as_ints()

    poly_array.to_multiprecision()
    poly_array.to_rns()

    poly_array_encoded_round_trip = poly_array.as_ints()

    assert poly_array_encoded_original == poly_array_encoded_round_trip
