from sealy import (BfvEncryptionParametersBuilder, CoefficientModulus, Context,
                   DegreeType, SecurityLevel)


def test_can_create_and_drop_context():
    # Create encryption parameters
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(1024))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(1024), [60, 40, 40, 60])
        )
        .with_plain_modulus_constant(1234)
        .build()
    )

    # Create context
    ctx = Context(params, False, SecurityLevel(128))

    # Drop context
    del ctx
