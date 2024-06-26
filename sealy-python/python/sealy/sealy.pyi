from typing import List

class MemoryPool:
    """
    Represents the memory pool used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new memory pool.
        """
        ...

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

    @classmethod
    def bfv(cls) -> "SchemeType":
        """
        Create a BFV scheme type.

        :return: A SchemeType instance for BFV.
        """
        ...

    @classmethod
    def ckks(cls) -> "SchemeType":
        """
        Create a CKKS scheme type.

        :return: A SchemeType instance for CKKS.
        """
        ...

class CoefficientModulus:
    """
    Represents the coefficient modulus used in encryption parameters.
    """

    @classmethod
    def create(
        cls, degree: "DegreeType", bit_sizes: List[int]
    ) -> List["Modulus"]:
        """
        Initialize a new coefficient modulus with a given degree and bit sizes.

        :param degree: The polynomial degree.
        :param bit_sizes: A list of bit sizes for the moduli.
        :return: A list of moduli.
        """
        ...

    @classmethod
    def ckks(
        cls, degree: "DegreeType", bit_sizes: List[int]
    ) -> List["Modulus"]:
        """
        Create a CKKS coefficient modulus.

        :param degree: The polynomial degree.
        :param bit_sizes: A list of bit sizes for the moduli.
        :return: A list of moduli.
        """
        ...

    @classmethod
    def bfv(
        cls, degree: "DegreeType", security_level: "SecurityLevel"
    ) -> List["Modulus"]:
        """
        Create a BFV coefficient modulus.

        :param degree: The polynomial degree.
        :param security_level: The security level.
        :return: A list of moduli.
        """
        ...

    @classmethod
    def max_bit_count(
        cls, degree: "DegreeType", security_level: "SecurityLevel"
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

    @classmethod
    def batching(cls, degree: "DegreeType", bit_size: int) -> "Modulus":
        """
        Create a plain modulus for batching.

        :param degree: The polynomial degree.
        :param bit_size: The bit size for the modulus.
        :return: The plain modulus.
        """
        ...

    @classmethod
    def raw(cls, val: int) -> "Modulus":
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

    @classmethod
    def default(cls) -> "SecurityLevel":
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

    @classmethod
    def get_block_size(cls) -> int:
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

class ContextData:
    """
    Represents the context data used in encryption parameters.
    """

    def get_encryption_parameters(self) -> "EncryptionParameters":
        """
        Get the encryption parameters from the context data.

        :return: The encryption parameters.
        """
        ...

    def get_total_coeff_modulus_bit_count(self) -> int:
        """
        Get the total coefficient modulus bit count from the context data.

        :return: The total coefficient modulus bit count.
        """
        ...

class Context:
    """
    Represents the context used in encryption parameters.
    """

    def __init__(
        self,
        params: "EncryptionParameters",
        expand_mod_chain: bool,
        security_level: "SecurityLevel",
    ) -> None:
        """
        Initialize a new context with given parameters.

        :param params: The encryption parameters.
        :param expand_mod_chain: A flag indicating whether to expand the modulus chain.
        :param security_level: The security level.
        """
        ...

    def get_key_parms_id(self) -> List[int]:
        """
        Get the key parameters ID from the context.

        :return: The key parameters ID.
        """
        ...

    def get_last_parms_id(self) -> int:
        """
        Get the last parameters ID from the context.

        :return: The last parameters ID.
        """
        ...

    def get_first_parms_id(self) -> int:
        """
        Get the first parameters ID from the context.

        :return: The first parameters ID.
        """
        ...

    def get_context_data(self) -> "ContextData":
        """
        Get the context data from the context.

        :return: The context data.
        """
        ...

class PublicKey:
    """
    Represents the public key used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new public key.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the public key to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(cls, context: "Context", data: bytes) -> "PublicKey":
        """
        Load the public key from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

class SecretKey:
    """
    Represents the secret key used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new secret key.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the secret key to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(cls, context: "Context", data: bytes) -> "SecretKey":
        """
        Load the secret key from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

class RelinearizationKey:
    """
    Represents the relinearization keys used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new relinearization keys.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the relinearization keys to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(
        cls, context: "Context", data: bytes
    ) -> "RelinearizationKey":
        """
        Load the relinearization keys from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

class GaloisKey:
    """
    Represents the Galois keys used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new Galois keys.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the Galois keys to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(cls, context: "Context", data: bytes) -> "GaloisKey":
        """
        Load the Galois keys from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

class KeyGenerator:
    """
    Represents the key generator used in encryption parameters.
    """

    def __init__(self, context: "Context") -> None:
        """
        Initialize a new key generator with a given context.

        :param context: The context for the key generator.
        """
        ...

    @classmethod
    def from_secret_key(
        cls, context: "Context", secret_key: "SecretKey"
    ) -> "KeyGenerator":
        """
        Generate a public key.

        :return: The public key.
        """
        ...

    def secret_key(self) -> "SecretKey":
        """
        Copies the secret key.

        :return: The secret key.
        """
        ...

    def create_public_key(self) -> "PublicKey":
        """
        Generate a public key.

        :return: The public key.
        """
        ...

    def create_galois_key(self) -> "GaloisKey":
        """
        Generate Galois keys.

        :return: The Galois keys.
        """
        ...

    def create_relinearization_key(self) -> "RelinearizationKey":
        """
        Generate relinearization keys.

        :return: The relinearization keys.
        """
        ...

class Plaintext:
    """
    Represents the plaintext used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new plaintext.
        """
        ...

    @classmethod
    def with_pool(cls, pool: "MemoryPool") -> "Plaintext":
        """
        Initialize a new plaintext with a given memory pool.

        :param pool: The memory pool.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the plaintext to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(cls, context: "Context", data: bytes) -> "Plaintext":
        """
        Load the plaintext from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

    @classmethod
    def from_hex_string(cls, hex_string: str) -> "Plaintext":
        """
        Load the plaintext from a hex string.

        :param hex_string: The hex string to load.
        """
        ...

    def get_coefficient(self, index: int) -> int:
        """
        Get the coefficient at a given index.

        :param index: The index of the coefficient.
        :return: The coefficient at the given index.
        """
        ...

    def set_coefficient(self, index: int, value: int) -> None:
        """
        Set the coefficient at a given index.

        :param index: The index of the coefficient.
        :param value: The value to set.
        """
        ...

    def resize(self, size: int) -> None:
        """
        Resize the plaintext to a given size.

        :param size: The size to resize to.
        """
        ...

    def size(self) -> int:
        """
        Get the size of the plaintext.

        :return: The size of the plaintext.
        """
        ...

    def is_ntt_form(self) -> bool:
        """
        Check if the plaintext is in NTT form.

        :return: True if the plaintext is in NTT form, False otherwise.
        """
        ...

class Ciphertext:
    """
    Represents the ciphertext used in encryption parameters.
    """

    def __init__(self) -> None:
        """
        Initialize a new ciphertext.
        """
        ...

    def as_bytes(self) -> bytes:
        """
        Convert the ciphertext to a list of bytes.
        """
        ...

    @classmethod
    def from_bytes(cls, context: "Context", data: bytes) -> "Ciphertext":
        """
        Load the ciphertext from a list of bytes.

        :param data: The list of bytes to load.
        """
        ...

    def get_num_polynomials(self) -> int:
        """
        Get the number of polynomials in the ciphertext.

        :return: The number of polynomials.
        """
        ...

    def get_coefficient(self, poly_index: int, coeff_index: int) -> int:
        """
        Get the coefficient at a given polynomial and coefficient index.

        :param poly_index: The polynomial index.
        :param coeff_index: The coefficient index.
        :return: The coefficient at the given polynomial and coefficient index.
        """
        ...

    def get_coeff_modulus_size(self) -> int:
        """
        Get the coefficient modulus size of the ciphertext.

        :return: The coefficient modulus size.
        """
        ...

    def is_ntt_form(self) -> bool:
        """
        Check if the ciphertext is in NTT form.

        :return: True if the ciphertext is in NTT form, False otherwise.
        """
        ...

from typing import List, Optional

class PolynomialArray:
    def __init__(self) -> None:
        """Creates a new empty polynomial array. Use an encoder to populate with a value."""
        ...

    @classmethod
    def from_ciphertext(
        cls, context: "Context", ciphertext: "Ciphertext"
    ) -> "PolynomialArray":
        """Creates a polynomial array from a reference to a ciphertext."""
        ...

    @classmethod
    def from_public_key(
        cls, context: "Context", public_key: "PublicKey"
    ) -> "PolynomialArray":
        """Creates a polynomial array from a reference to a public key."""
        ...

    @classmethod
    def from_secret_key(
        cls, context: "Context", secret_key: "SecretKey"
    ) -> "PolynomialArray":
        """Creates a polynomial array from a reference to a secret key."""
        ...

    def is_reserved(self) -> bool:
        """Has the array data been loaded? When an array is created, it initially
        has no data. Once data is loaded this is true. Additionally data can only
        be loaded once."""
        ...

    def is_rns(self) -> bool:
        """Is the array in RNS form (true)."""
        ...

    def is_multiprecision(self) -> bool:
        """Is the array in RNS form (true)."""
        ...

    def to_rns(self) -> None:
        """Converts the polynomial array into the RNS format regardless of its
        current format."""
        ...

    def to_multiprecision(self) -> None:
        """Converts the polynomial array into the multiprecision format regardless
        of its current format."""
        ...

    def as_multiprecision_bytes(self) -> bytes:
        """This will be in coefficient order; all the limbs with a given coefficient
        are stored together in least significant order.

        The number of limbs equals the number of moduli in the coefficient
        modulus."""
        ...

    def as_rns_bytes(self) -> bytes:
        """This will be in modulus order; all the values associated with a given
        moduli are stored together.

        The number of limbs equals the number of moduli in the coefficient
        modulus."""
        ...

    def get_num_polynomials(self) -> int:
        """Returns the number of polynomials stored in the `PolynomialArray`."""
        ...

    def get_poly_modulus_degree(self) -> int:
        """Returns the number of coefficients in each polynomial in the `PolynomialArray`."""
        ...

    def get_coeff_modulus_size(self) -> int:
        """Returns how many moduli are in the coefficient modulus set."""
        ...

    def drop_modulus(self) -> "PolynomialArray":
        """Reduces the polynomial array by dropping the last modulus in the modulus
        set."""
        ...
