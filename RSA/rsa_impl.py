import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Sha256"))
try:
    from sha256_impl import sha256 as _sha256
except ImportError:
    import hashlib
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


def extended_gcd(a: int, b: int):
    """Retorna (mdc, x, y) tal que a*x + b*y = mdc."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(a: int, m: int) -> int:
    """Retorna o inverso modular x tal que a*x ≡ 1 (mod m)."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Inverso modular não existe: mdc({a}, {m}) = {gcd}")
    return x % m


def is_prime(n: int, rounds: int = 20) -> bool:
    """Teste de primalidade probabilístico de Miller-Rabin."""
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Gera um número primo aleatório de exatamente `bits` bits."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def generate_keypair(bits: int = 512):
    """Gera um par de chaves RSA (chave_publica, chave_privada) com primos de `bits` bits."""
    e = 65537

    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue

        n = p * q
        phi_n = (p - 1) * (q - 1)

        if phi_n % e == 0:
            continue

        try:
            d = mod_inverse(e, phi_n)
        except ValueError:
            continue

        return (e, n), (d, n)


def _int_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def encrypt(plaintext: str, public_key: tuple) -> list:
    """Cifra uma string em blocos RSA. Retorna lista de inteiros cifrados."""
    e, n = public_key
    key_bytes = (n.bit_length() + 7) // 8
    block_size = key_bytes - 2

    data = plaintext.encode("utf-8")
    if not data:
        data = b""

    blocks = []
    for i in range(0, max(len(data), 1), block_size):
        chunk = data[i : i + block_size]
        padded = b"\x01" + chunk
        m = _bytes_to_int(padded)
        if m >= n:
            raise ValueError("Bloco excede o módulo n — use chaves maiores.")
        blocks.append(pow(m, e, n))
    return blocks


def decrypt(ciphertext_blocks: list, private_key: tuple) -> str:
    """Decifra lista de blocos RSA em string."""
    d, n = private_key
    parts = []
    for c in ciphertext_blocks:
        m = pow(c, d, n)
        raw = _int_to_bytes(m)
        if raw[:1] != b"\x01":
            raise ValueError("Bloco inválido: dado corrompido ou chave incorreta.")
        parts.append(raw[1:])
    return b"".join(parts).decode("utf-8")


def sign(message: str, private_key: tuple) -> int:
    """Assina uma mensagem com a chave privada usando RSA-SHA256."""
    d, n = private_key
    h = int(_sha256(message.encode("utf-8")), 16)
    return pow(h, d, n)


def verify(message: str, signature: int, public_key: tuple) -> bool:
    """Verifica uma assinatura RSA-SHA256."""
    e, n = public_key
    h_expected = int(_sha256(message.encode("utf-8")), 16)
    h_recovered = pow(signature, e, n)
    return h_recovered == h_expected


def key_to_dict(key: tuple) -> dict:
    """Converte chave (exp, mod) para dicionário serializável em JSON."""
    exp, mod = key
    return {"exp": exp, "mod": mod}


def key_from_dict(d: dict) -> tuple:
    """Reconstrói chave a partir de dicionário."""
    return (int(d["exp"]), int(d["mod"]))


def _demo():
    """Demonstra cifragem, decifragem e assinatura RSA."""
    print("=" * 65)
    print("RSA -- Implementação Educacional (Python Puro)")
    print("=" * 65)

    print("\n[1] Gerando par de chaves RSA (primos de 512 bits => chave ~1024 bits)...")
    print("    (pode levar alguns segundos)\n")
    pub, priv = generate_keypair(bits=512)

    e, n = pub
    d, _ = priv
    print(f"    e (público) = {e}")
    print(f"    n (módulo)  = {str(n)[:40]}...")
    print(f"    d (privado) = {str(d)[:40]}...")

    mensagens = [
        "Olá!",
        "RSA funciona.",
        "Criptografia ponta a ponta no chat.",
        "x" * 200,
    ]

    print("\n[2] Cifragem e Decifragem")
    print("    " + "-" * 50)
    all_ok = True
    for msg in mensagens:
        blocks = encrypt(msg, pub)
        recovered = decrypt(blocks, priv)
        ok = recovered == msg
        if not ok:
            all_ok = False
        label = repr(msg) if len(msg) <= 30 else repr(msg[:27]) + "..."
        print(f"    [{'OK' if ok else 'FALHA'}] {label} => {len(blocks)} bloco(s)")

    msg_teste = "Mensagem autenticada com RSA-SHA256."
    sig = sign(msg_teste, priv)
    valid_original = verify(msg_teste, sig, pub)
    valid_tampered = verify(msg_teste + "!", sig, pub)

    print("\n[3] Assinatura Digital RSA-SHA256")
    print("    " + "-" * 50)
    print(f"    Mensagem  : {msg_teste!r}")
    print(f"    Assinatura: {hex(sig)[:40]}...")
    print(f"    Verificação (original) : {'OK' if valid_original else 'FALHA'}")
    print(f"    Verificação (adulterada): {'FALHA (esperado)' if not valid_tampered else 'ERRO!'}")

    print("\n" + "=" * 65)
    resultado = all_ok and valid_original and not valid_tampered
    print("Resultado:", "TODOS OS TESTES PASSARAM" if resultado else "ERROS ENCONTRADOS")


if __name__ == "__main__":
    _demo()
