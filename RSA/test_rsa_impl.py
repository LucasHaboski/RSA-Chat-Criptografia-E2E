import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "Sha256"))

from rsa_impl import (
    extended_gcd,
    mod_inverse,
    is_prime,
    generate_prime,
    generate_keypair,
    encrypt,
    decrypt,
    sign,
    verify,
    key_to_dict,
    key_from_dict,
)


@pytest.fixture(scope="module")
def keypair_256():
    """Par de chaves 256 bits gerado uma vez por sessão de testes."""
    return generate_keypair(bits=256)


class TestExtendedGcd:
    def test_basic(self):
        gcd, x, y = extended_gcd(35, 15)
        assert gcd == 5
        assert 35 * x + 15 * y == gcd

    def test_coprimes(self):
        gcd, x, y = extended_gcd(17, 13)
        assert gcd == 1
        assert 17 * x + 13 * y == 1

    def test_zero_input(self):
        gcd, x, y = extended_gcd(0, 7)
        assert gcd == 7


class TestModInverse:
    def test_known_value(self):
        assert mod_inverse(3, 5) == 2

    def test_large_values(self):
        a, m = 65537, (2**127 - 1)
        inv = mod_inverse(a, m)
        assert (a * inv) % m == 1

    def test_no_inverse_raises(self):
        with pytest.raises(ValueError):
            mod_inverse(4, 6)


class TestIsPrime:
    KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 97, 101, 7919, 104729]
    KNOWN_COMPOSITES = [0, 1, 4, 6, 8, 9, 100, 1024, 104728]

    @pytest.mark.parametrize("p", KNOWN_PRIMES)
    def test_primes(self, p):
        assert is_prime(p), f"{p} deveria ser primo"

    @pytest.mark.parametrize("c", KNOWN_COMPOSITES)
    def test_composites(self, c):
        assert not is_prime(c), f"{c} não deveria ser primo"

    def test_large_prime(self):
        assert is_prime(2**127 - 1)


class TestGeneratePrime:
    def test_is_prime(self):
        p = generate_prime(128)
        assert is_prime(p)

    def test_correct_bit_length(self):
        p = generate_prime(128)
        assert p.bit_length() == 128


class TestGenerateKeypair:
    def test_returns_two_tuples(self, keypair_256):
        pub, priv = keypair_256
        assert len(pub) == 2
        assert len(priv) == 2

    def test_same_modulus(self, keypair_256):
        pub, priv = keypair_256
        assert pub[1] == priv[1]

    def test_public_exponent_is_65537(self, keypair_256):
        pub, _ = keypair_256
        assert pub[0] == 65537

    def test_encrypt_decrypt_identity(self, keypair_256):
        pub, priv = keypair_256
        msg = "teste de identidade RSA"
        assert decrypt(encrypt(msg, pub), priv) == msg


class TestEncryptDecrypt:
    def test_short_message(self, keypair_256):
        pub, priv = keypair_256
        msg = "Olá!"
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_empty_string(self, keypair_256):
        pub, priv = keypair_256
        msg = ""
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_unicode(self, keypair_256):
        pub, priv = keypair_256
        msg = "criptografia: αβγδ — 日本語 🔐"
        assert decrypt(encrypt(msg, pub), priv) == msg

    def test_long_message_multiple_blocks(self, keypair_256):
        pub, priv = keypair_256
        msg = "A" * 500
        blocks = encrypt(msg, pub)
        assert len(blocks) > 1
        assert decrypt(blocks, priv) == msg

    def test_wrong_key_raises(self, keypair_256):
        pub, priv = keypair_256
        pub2, priv2 = generate_keypair(bits=256)
        msg = "segredo"
        blocks = encrypt(msg, pub)
        with pytest.raises(Exception):
            decrypt(blocks, priv2)

    def test_ciphertext_is_list_of_ints(self, keypair_256):
        pub, _ = keypair_256
        blocks = encrypt("hello", pub)
        assert isinstance(blocks, list)
        assert all(isinstance(b, int) for b in blocks)

    def test_same_message_deterministic_with_same_key(self, keypair_256):
        pub, priv = keypair_256
        msg = "determinismo"
        assert encrypt(msg, pub) == encrypt(msg, pub)

    def test_different_messages_different_ciphertexts(self, keypair_256):
        pub, _ = keypair_256
        assert encrypt("mensagem A", pub) != encrypt("mensagem B", pub)


class TestSignVerify:
    def test_valid_signature(self, keypair_256):
        pub, priv = keypair_256
        msg = "mensagem autenticada"
        sig = sign(msg, priv)
        assert verify(msg, sig, pub)

    def test_tampered_message_fails(self, keypair_256):
        pub, priv = keypair_256
        msg = "mensagem original"
        sig = sign(msg, priv)
        assert not verify(msg + "!", sig, pub)

    def test_wrong_key_fails(self, keypair_256):
        pub, priv = keypair_256
        pub2, _ = generate_keypair(bits=256)
        msg = "mensagem"
        sig = sign(msg, priv)
        assert not verify(msg, sig, pub2)

    def test_empty_message(self, keypair_256):
        pub, priv = keypair_256
        msg = ""
        sig = sign(msg, priv)
        assert verify(msg, sig, pub)

    def test_signature_is_int(self, keypair_256):
        _, priv = keypair_256
        sig = sign("teste", priv)
        assert isinstance(sig, int)


class TestSerialization:
    def test_roundtrip(self, keypair_256):
        pub, priv = keypair_256
        assert key_from_dict(key_to_dict(pub)) == pub
        assert key_from_dict(key_to_dict(priv)) == priv

    def test_dict_has_exp_and_mod(self, keypair_256):
        pub, _ = keypair_256
        d = key_to_dict(pub)
        assert "exp" in d and "mod" in d
