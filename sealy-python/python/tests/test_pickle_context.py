import os
import pickle
import tempfile

from sealy import (BfvEncryptionParametersBuilder, CoefficientModulus, Context,
                   DegreeType, SecurityLevel)


def test_pickle_context():
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
    ctx = Context.build(params, False, SecurityLevel(128))

    # create a temporary file
    temp_file = tempfile.mktemp()

    # Save the context to the file
    with open(temp_file, "wb") as f:
        pickle.dump(ctx, f)

    # Load the context from the file
    with open(temp_file, "rb") as f:
        ctx_2: Context = pickle.load(f)

    assert len(ctx_2.get_key_parms_id()) > 0
    assert len(ctx_2.get_last_parms_id()) > 0
    assert len(ctx_2.get_last_parms_id()) > 0
