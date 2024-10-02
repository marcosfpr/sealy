from sealy import (BfvEncryptionParametersBuilder, CoefficientModulus, Context,
                   DegreeType, Encryptor, KeyGenerator, SecurityLevel)
from sealy.sealy import BFVEncoder, Decryptor, PlainModulus


def test_can_encrypt_and_decrypt_unsigned():
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

    gen = KeyGenerator(ctx)

    encoder = BFVEncoder(ctx)

    data = [i for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_int(data)

    public_key = gen.create_public_key()
    secret_key = gen.secret_key()

    encryptor = Encryptor(ctx, public_key)
    decryptor = Decryptor(ctx, secret_key)

    # Asymmetric test
    ciphertext = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(ciphertext)
    data_2 = encoder.decode_int(decrypted)
    assert data == data_2


def test_can_encrypt_and_decrypt_from_return_components():

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

    gen = KeyGenerator(ctx)

    encoder = BFVEncoder(ctx)

    data = [i for i in range(encoder.get_slot_count())]

    plaintext = encoder.encode_int(data)

    public_key = gen.create_public_key()
    secret_key = gen.secret_key()

    encryptor = Encryptor(ctx, public_key)
    decryptor = Decryptor(ctx, secret_key)

    # Asymmetric test
    ciphertext = encryptor.encrypt_return_components(plaintext)[0]
    decrypted = decryptor.decrypt(ciphertext)
    data_2 = encoder.decode_int(decrypted)
    assert data == data_2

    # Symmetric test
    ciphertext = encryptor.encrypt_return_components(plaintext)[0]
    decrypted = decryptor.decrypt(ciphertext)
    data_2 = encoder.decode_int(decrypted)
    assert data == data_2
