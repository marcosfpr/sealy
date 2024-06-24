from typing import List

class SchemeType:
    """
    Represents a scheme type used in encryption parameters.
    """

    def __init__(self, val: int) -> None:
        """
        Initialize a new SchemeType with a given value.

        :param val: The value representing the scheme type.
        """
        ...

    @staticmethod
    def bfv() -> "SchemeType":
        """
        Create a BFV scheme type.

        :return: A SchemeType instance for BFV.
        """
        ...

    @staticmethod
    def ckks() -> "SchemeType":
        """
        Create a CKKS scheme type.

        :return: A SchemeType instance for CKKS.
        """
        ...

class CoefficientModulus:
    """
    Represents the coefficient modulus used in encryption parameters.
    """

    @staticmethod
    def create(degree: "DegreeType", bit_sizes: List[int]) -> List["Modulus"]:
        """
        Initialize a new coefficient modulus with a given degree and bit sizes.

        :param degree: The polynomial degree.
        :param bit_sizes: A list of bit sizes for the moduli.
        :return: A list of moduli.
        """
        ...

    @staticmethod
    def ckks(degree: "DegreeType", bit_sizes: List[int]) -> List["Modulus"]:
        """
        Create a CKKS coefficient modulus.

        :param degree: The polynomial degree.
        :param bit_sizes: A list of bit sizes for the moduli.
        :return: A list of moduli.
        """
        ...

    @staticmethod
    def bfv(
        degree: "DegreeType", security_level: "SecurityLevel"
    ) -> List["Modulus"]:
        """
        Create a BFV coefficient modulus.

        :param degree: The polynomial degree.
        :param security_level: The security level.
        :return: A list of moduli.
        """
        ...

    @staticmethod
    def max_bit_count(
        degree: "DegreeType", security_level: "SecurityLevel"
    ) -> int:
        """
        Get the maximum bit count for a given degree and security level.

        :param degree: The polynomial degree.
        :param security_level: The security level.
        :return: The maximum bit count.
        """
        ...

class PlainModulus:
    """
    Represents the plain modulus used in encryption parameters.
    """

    @staticmethod
    def batching(degree: "DegreeType", bit_size: int) -> "Modulus":
        """
        Create a plain modulus for batching.

        :param degree: The polynomial degree.
        :param bit_size: The bit size for the modulus.
        :return: The plain modulus.
        """
        ...

    @staticmethod
    def raw(val: int) -> "Modulus":
        """
        Create a plain modulus from a raw value.

        :param val: The raw value for the modulus.
        :return: The plain modulus.
        """
        ...

class Modulus:
    """
    Represents a modulus used in encryption parameters.
    """

    def __init__(self, value: int) -> None:
        """
        Initialize a new modulus with a given value.

        :param value: The value of the modulus.
        """
        ...

    def get_value(self) -> int:
        """
        Get the value of the modulus.

        :return: The value of the modulus.
        """
        ...

class DegreeType:
    """
    Represents a degree type used in encryption parameters.
    """

    def __init__(self, degree: int) -> None:
        """
        Initialize a new degree type with a given value.

        :param degree: The degree value.
        """
        ...

class SecurityLevel:
    """
    Represents a security level used in encryption parameters.
    """

    def __init__(self, value: int) -> None:
        """
        Initialize a new security level with a given value.

        :param value: The security level value.
        """
        ...

    @staticmethod
    def default() -> "SecurityLevel":
        """
        Get the default security level.

        :return: The default security level.
        """
        ...

    def get_value(self) -> int:
        """
        Get the value of the security level.

        :return: The value of the security level.
        """
        ...

class EncryptionParameters:
    """
    Represents the encryption parameters for the scheme.
    """

    def __init__(self, scheme: SchemeType) -> None:
        """
        Initialize encryption parameters with a given scheme type.

        :param scheme: The scheme type for the encryption parameters.
        """
        ...

    @staticmethod
    def get_block_size() -> int:
        """
        Get the block size of the encryption parameters.

        :return: The block size.
        """
        ...

    def get_poly_modulus_degree(self) -> int:
        """
        Get the polynomial modulus degree of the encryption parameters.

        :return: The polynomial modulus degree.
        """
        ...

    def get_scheme(self) -> SchemeType:
        """
        Get the scheme type of the encryption parameters.

        :return: The scheme type.
        """
        ...

    def get_plain_modulus(self) -> "Modulus":
        """
        Get the plain modulus of the encryption parameters.

        :return: The plain modulus.
        """
        ...

    def get_coefficient_modulus(self) -> List["Modulus"]:
        """
        Get the coefficient modulus of the encryption parameters.

        :return: A list of coefficient moduli.
        """
        ...

    def get_parms_id(self) -> int:
        """
        Get the parameters ID of the encryption parameters.

        :return: The parameters ID.
        """
        ...

    def set_coefficient_modulus(self, modulus: List["Modulus"]) -> None:
        """
        Set the coefficient modulus of the encryption parameters.

        :param modulus: A list of coefficient moduli to set.
        """
        ...

    def set_poly_modulus_degree(self, degree: "DegreeType") -> None:
        """
        Set the polynomial modulus degree of the encryption parameters.

        :param degree: The polynomial modulus degree to set.
        """
        ...

    def set_plain_modulus(self, modulus: "Modulus") -> None:
        """
        Set the plain modulus of the encryption parameters.

        :param modulus: The plain modulus to set.
        """
        ...

    def set_plain_modulus_constant(self, modulus: int) -> None:
        """
        Set the plain modulus of the encryption parameters using a constant value.

        :param modulus: The constant value for the plain modulus.
        """
        ...
