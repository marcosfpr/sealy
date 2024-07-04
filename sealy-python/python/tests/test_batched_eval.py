import random
from typing import List

import pytest
from sealy import (BatchDecryptor, BatchEncryptor, CiphertextBatchArray,
                   CKKSBatchEncoder, CKKSBatchEvaluator,
                   CkksEncryptionParametersBuilder, CoefficientModulus,
                   Context, DegreeType, KeyGenerator, SecurityLevel)


def generate_random_tensor(size):
    return [random.uniform(0.0, 1.0) for _ in range(size)]


def average_ciphertexts(
    ctx: Context,
    encoder: CKKSBatchEncoder,
    ciphertexts: List[CiphertextBatchArray],
    size: int,
):
    evaluator = CKKSBatchEvaluator(ctx)

    cipher = evaluator.add_many(ciphertexts)

    fraction = 1.0 / len(ciphertexts)
    fraction = [fraction] * size
    fraction = encoder.encode(fraction)

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
    return CKKSBatchEncoder(context, 2**40)


@pytest.fixture
def encryptor(context: Context, key_generator: KeyGenerator):
    public_key = key_generator.create_public_key()
    return BatchEncryptor(context, public_key)


@pytest.fixture
def decryptor(context: Context, key_generator: KeyGenerator):
    private_key = key_generator.secret_key()
    return BatchDecryptor(context, private_key)


def test_average_ciphertexts(
    context: Context,
    encoder: CKKSBatchEncoder,
    encryptor: BatchEncryptor,
    decryptor: BatchDecryptor,
):
    client_1_gradients = generate_random_tensor(11000)
    client_2_gradients = generate_random_tensor(11000)
    client_3_gradients = generate_random_tensor(11000)

    client_1_encoded_gradients = encoder.encode(client_1_gradients)
    client_2_encoded_gradients = encoder.encode(client_2_gradients)
    client_3_encoded_gradients = encoder.encode(client_3_gradients)

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
    avg_plain = encoder.decode(avg_dec)

    avg_plain = avg_plain[:10]

    for t, p in zip(avg_truth, avg_plain):
        assert abs(t - p) < 1e-6
