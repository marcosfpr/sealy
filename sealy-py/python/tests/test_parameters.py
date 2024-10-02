from sealy import (BfvEncryptionParametersBuilder,
                   CkksEncryptionParametersBuilder, CoefficientModulus,
                   DegreeType, PlainModulus, SchemeType, SecurityLevel)


def test_can_create_plain_modulus():
    modulus = PlainModulus.batching(DegreeType(1024), 20)
    assert modulus.get_value() == 1038337


def test_can_create_default_coefficient_modulus():
    modulus = CoefficientModulus.bfv(DegreeType(1024), SecurityLevel(128))
    assert len(modulus) == 1
    assert modulus[0].get_value() == 132120577

    modulus = CoefficientModulus.bfv(DegreeType(1024), SecurityLevel(192))
    assert len(modulus) == 1
    assert modulus[0].get_value() == 520193

    modulus = CoefficientModulus.bfv(DegreeType(1024), SecurityLevel(256))
    assert len(modulus) == 1
    assert modulus[0].get_value() == 12289


def test_can_create_custom_coefficient_modulus():
    modulus = CoefficientModulus.ckks(DegreeType(8192), [50, 30, 30, 50, 50])
    assert len(modulus) == 5
    assert modulus[0].get_value() == 1125899905744897
    assert modulus[1].get_value() == 1073643521
    assert modulus[2].get_value() == 1073692673
    assert modulus[3].get_value() == 1125899906629633
    assert modulus[4].get_value() == 1125899906826241


def test_can_roundtrip_security_level():
    for sec in [SecurityLevel(128), SecurityLevel(192), SecurityLevel(256)]:
        sec_2 = SecurityLevel(sec.get_value())
        assert sec == sec_2


def test_can_build_ckks_params():
    bit_sizes = [60, 40, 40, 60]
    modulus_chain = CoefficientModulus.ckks(DegreeType(1024), bit_sizes)

    params = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(1024))
        .with_coefficient_modulus(modulus_chain)
        .build()
    )

    assert params.get_poly_modulus_degree() == 1024
    assert params.get_scheme() == SchemeType.ckks()
    assert len(params.get_coefficient_modulus()) == 4

    params = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(1024))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
    ).build()

    modulus = params.get_coefficient_modulus()
    assert modulus[0].get_value() == 1125899905744897
    assert modulus[1].get_value() == 1073643521
    assert modulus[2].get_value() == 1073692673
    assert modulus[3].get_value() == 1125899906629633
    assert modulus[4].get_value() == 1125899906826241


def test_can_build_bfv_params():
    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(1024))
        .with_coefficient_modulus(
            CoefficientModulus.bfv(DegreeType(1024), SecurityLevel.default())
        )
        .with_plain_modulus_constant(1234)
    ).build()

    assert params.get_poly_modulus_degree() == 1024
    assert params.get_scheme() == SchemeType.bfv()
    assert params.get_plain_modulus().get_value() == 1234
    assert len(params.get_coefficient_modulus()) == 1
    assert params.get_coefficient_modulus()[0].get_value() == 132120577

    params = (
        BfvEncryptionParametersBuilder()
        .with_poly_modulus_degree(DegreeType(1024))
        .with_coefficient_modulus(
            CoefficientModulus.create(DegreeType(8192), [50, 30, 30, 50, 50])
        )
        .with_plain_modulus_constant(1234)
    ).build()

    modulus = params.get_coefficient_modulus()
    assert modulus[0].get_value() == 1125899905744897
    assert modulus[1].get_value() == 1073643521
    assert modulus[2].get_value() == 1073692673
    assert modulus[3].get_value() == 1125899906629633
    assert modulus[4].get_value() == 1125899906826241
