from sealy import Plaintext


def test_can_create_and_destroy_plaintext():
    plaintext = Plaintext()
    del plaintext


def test_plaintext_coefficients_in_increasing_order():
    plaintext = Plaintext.from_hex_string("1234x^2 + 4321")

    assert plaintext.get_coefficient(0) == 0x4321
    assert plaintext.get_coefficient(1) == 0
    assert plaintext.get_coefficient(2) == 0x1234
