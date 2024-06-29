from typing import List

from sealy.sealy import DegreeType, EncryptionParameters, Modulus, SchemeType


class BfvEncryptionParametersBuilder:
    """Constructs BFV encryption"""

    def __init__(self) -> None:
        """Initializes a new instance of the BfvEncryptionParametersBuilder class."""
        self.poly_modulus_degree = None
        self.coeff_modulus = None
        self.plain_modulus = None

    def with_poly_modulus_degree(
        self, poly_modulus_degree: DegreeType
    ) -> "BfvEncryptionParametersBuilder":
        """Sets the polynomial degree of the underlying BFV scheme."""
        self.poly_modulus_degree = poly_modulus_degree
        return self

    def with_coefficient_modulus(
        self, coeff_modulus: List[Modulus]
    ) -> "BfvEncryptionParametersBuilder":
        """Sets the coefficient modulus for the encryption scheme."""
        self.coeff_modulus = coeff_modulus
        return self

    def with_plain_modulus(
        self, plain_modulus: Modulus
    ) -> "BfvEncryptionParametersBuilder":
        """Sets the plaintext modulus for the encryption scheme."""
        self.plain_modulus = plain_modulus
        return self

    def with_plain_modulus_constant(
        self, plain_modulus: int
    ) -> "BfvEncryptionParametersBuilder":
        """Sets the plaintext modulus for the encryption scheme."""
        self.plain_modulus = Modulus(plain_modulus)
        return self

    def build(self) -> EncryptionParameters:
        """Builds a new instance of the BfvEncryptionParameters class."""
        params = EncryptionParameters(SchemeType.bfv())

        if self.poly_modulus_degree is not None:
            params.set_poly_modulus_degree(self.poly_modulus_degree)
        else:
            raise ValueError("poly_modulus_degree cannot be None")

        if self.coeff_modulus is not None:
            params.set_coefficient_modulus(self.coeff_modulus)
        else:
            raise ValueError("coeff_modulus cannot be None")

        if self.plain_modulus is not None:
            if isinstance(self.plain_modulus, Modulus):
                params.set_plain_modulus(self.plain_modulus)
            elif isinstance(self.plain_modulus, int):
                params.set_plain_modulus_constant(self.plain_modulus)
            else:
                raise ValueError("plain_modulus must be Modulus or int")
        else:
            raise ValueError("plain_modulus cannot be None")

        return params


class CkksEncryptionParametersBuilder:
    """Constructs CKKS encryption"""

    def __init__(self) -> None:
        """Initializes a new instance of the CkksEncryptionParametersBuilder class."""
        self.poly_modulus_degree = None
        self.coeff_modulus = None

    def with_poly_modulus_degree(
        self, poly_modulus_degree: DegreeType
    ) -> "CkksEncryptionParametersBuilder":
        """Sets the polynomial degree of the underlying CKKS scheme."""
        self.poly_modulus_degree = poly_modulus_degree
        return self

    def with_coefficient_modulus(
        self, coeff_modulus: List[Modulus]
    ) -> "CkksEncryptionParametersBuilder":
        """Sets the coefficient modulus for the encryption scheme."""
        self.coeff_modulus = coeff_modulus
        return self

    def build(self) -> EncryptionParameters:
        """Builds a new instance of the CkksEncryptionParameters class."""
        params = EncryptionParameters(SchemeType.ckks())

        if self.poly_modulus_degree is not None:
            params.set_poly_modulus_degree(self.poly_modulus_degree)
        else:
            raise ValueError("poly_modulus_degree cannot be None")

        if self.coeff_modulus is not None:
            params.set_coefficient_modulus(self.coeff_modulus)
        else:
            raise ValueError("coeff_modulus cannot be None")

        return params
