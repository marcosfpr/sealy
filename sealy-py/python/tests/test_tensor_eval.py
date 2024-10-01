import random
from typing import List

import pytest
from sealy import (CiphertextTensor, CkksEncryptionParametersBuilder,
                   CKKSTensorEncoder, CKKSTensorEvaluator, CoefficientModulus,
                   Context, DegreeType, KeyGenerator, SecurityLevel,
                   TensorDecryptor, TensorEncryptor)


def generate_random_tensor(size):
    return [random.uniform(0.0, 1.0) for _ in range(size)]


def average_ciphertexts(
    ctx: Context,
    encoder: CKKSTensorEncoder,
    ciphertexts: List[CiphertextTensor],
    size: int,
):
    evaluator = CKKSTensorEvaluator(ctx)

    cipher = evaluator.add_many(ciphertexts)

    fraction = 1.0 / len(ciphertexts)
    fraction = [fraction] * size
    fraction = encoder.encode_float(fraction)

    return evaluator.multiply_plain(cipher, fraction)


def average_plaintexts(plaintexts):
    avg = [0.0] * len(plaintexts[0])
    for tensor in plaintexts:
        for i, val in enumerate(tensor):
            avg[i] += val
    return [val / len(plaintexts) for val in avg]


@pytest.fixture
def context() -> Context:
    degree = DegreeType(8192)
    security_level = SecurityLevel(128)
    bit_sizes = [60, 40, 40, 60]

    expand_mod_chain = False
    modulus_chain = CoefficientModulus.create(degree, bit_sizes)
    encryption_parameters = (
        CkksEncryptionParametersBuilder()
        .with_poly_modulus_degree(degree)
        .with_coefficient_modulus(modulus_chain)
        .build()
    )

    return Context(encryption_parameters, expand_mod_chain, security_level)


@pytest.fixture
def key_generator(context: Context):
    return KeyGenerator(context)


@pytest.fixture
def encoder(context: Context):
    return CKKSTensorEncoder(context, 2**40)


@pytest.fixture
def encryptor(context: Context, key_generator: KeyGenerator):
    public_key = key_generator.create_public_key()
    return TensorEncryptor(context, public_key)


@pytest.fixture
def decryptor(context: Context, key_generator: KeyGenerator):
    private_key = key_generator.secret_key()
    return TensorDecryptor(context, private_key)


def test_average_ciphertexts(
    context: Context,
    encoder: CKKSTensorEncoder,
    encryptor: TensorEncryptor,
    decryptor: TensorDecryptor,
):
    client_1_gradients = generate_random_tensor(11000)
    client_2_gradients = generate_random_tensor(11000)
    client_3_gradients = generate_random_tensor(11000)

    client_1_encoded_gradients = encoder.encode_float(client_1_gradients)
    client_2_encoded_gradients = encoder.encode_float(client_2_gradients)
    client_3_encoded_gradients = encoder.encode_float(client_3_gradients)

    client_1_encrypted_gradients = encryptor.encrypt(
        client_1_encoded_gradients
    )
    client_2_encrypted_gradients = encryptor.encrypt(
        client_2_encoded_gradients
    )
    client_3_encrypted_gradients = encryptor.encrypt(
        client_3_encoded_gradients
    )

    avg_truth = average_plaintexts(
        [client_1_gradients, client_2_gradients, client_3_gradients]
    )

    avg = average_ciphertexts(
        context,
        encoder,
        [
            client_1_encrypted_gradients,
            client_2_encrypted_gradients,
            client_3_encrypted_gradients,
        ],
        10,
    )

    avg_dec = decryptor.decrypt(avg)
    avg_plain = encoder.decode_float(avg_dec)

    avg_plain = avg_plain[:10]

    for t, p in zip(avg_truth, avg_plain):
        assert abs(t - p) < 1e-6
