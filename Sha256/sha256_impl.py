import struct
from typing import List


H = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

MASK32 = 0xFFFFFFFF


def rotr(x: int, n: int) -> int:
    """Rotação circular para a direita em 32 bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr(x: int, n: int) -> int:
    """Deslocamento lógico para a direita."""
    return (x >> n) & MASK32


def ch(x: int, y: int, z: int) -> int:
    """Função Ch: (x AND y) XOR (NOT x AND z)."""
    return (x & y) ^ (~x & z) & MASK32


def maj(x: int, y: int, z: int) -> int:
    """Função Maj: (x AND y) XOR (x AND z) XOR (y AND z)."""
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x: int) -> int:
    """Sigma0: ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma1(x: int) -> int:
    """Sigma1: ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def gamma0(x: int) -> int:
    """Gamma0: ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)."""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def gamma1(x: int) -> int:
    """Gamma1: ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)."""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def pad_message(message: bytes) -> bytes:
    """Aplica o padding SHA256: adiciona bit 1, zeros e comprimento em 64 bits big-endian."""
    msg_len_bits = len(message) * 8
    message += b"\x80"
    while (len(message) % 64) != 56:
        message += b"\x00"
    message += struct.pack(">Q", msg_len_bits)
    return message


def sha256(message: bytes) -> str:
    """Calcula o hash SHA256 de uma mensagem em bytes. Retorna string hexadecimal de 64 chars."""
    padded = pad_message(message)
    h0, h1, h2, h3, h4, h5, h6, h7 = H[:]

    for block_start in range(0, len(padded), 64):
        block = padded[block_start : block_start + 64]

        W: List[int] = list(struct.unpack(">16I", block))
        for t in range(16, 64):
            w = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) & MASK32
            W.append(w)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for t in range(64):
            T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) & MASK32
            T2 = (sigma0(a) + maj(a, b, c)) & MASK32
            h = g
            g = f
            f = e
            e = (d + T1) & MASK32
            d = c
            c = b
            b = a
            a = (T1 + T2) & MASK32

        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32
        h5 = (h5 + f) & MASK32
        h6 = (h6 + g) & MASK32
        h7 = (h7 + h) & MASK32

    digest = struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)
    return digest.hex()


def sha256_file(filepath: str) -> str:
    """Calcula o SHA256 de um arquivo."""
    with open(filepath, "rb") as f:
        data = f.read()
    return sha256(data)


def _demo():
    """Demonstra o algoritmo com vetores de teste NIST."""
    import hashlib

    test_vectors = [
        b"",
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    ]

    print("=" * 64)
    print("SHA256 -- Implementacao Educacional vs hashlib")
    print("=" * 64)

    all_pass = True
    for msg in test_vectors:
        expected = hashlib.sha256(msg).hexdigest()
        computed = sha256(msg)
        status = "PASS" if computed == expected else "FAIL"
        if status == "FAIL":
            all_pass = False
        label = repr(msg) if len(msg) <= 8 else repr(msg[:8]) + "..."
        print(f"  [{status}] {label}")
        print(f"         Esperado: {expected}")
        print(f"         Calculado:{computed}")

    print("=" * 64)
    print("Resultado:", "TODOS OK" if all_pass else "ERROS ENCONTRADOS")


if __name__ == "__main__":
    _demo()
