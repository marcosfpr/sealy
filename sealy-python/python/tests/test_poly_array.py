from sealy import (BfvEncryptionParametersBuilder, Ciphertext,
                   CoefficientModulus, Context, DegreeType, PolynomialArray,
                   SecurityLevel)


def test_can_create_and_destroy_static_polynomial_array():
    poly_array = PolynomialArray()
    del poly_array


def test_can_create_polynomial_from_ciphertext():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(8192))
        .with_coeff_modulus(
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
