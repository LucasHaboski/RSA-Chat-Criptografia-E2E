"""Cliente terminal com criptografia ponta a ponta usando RSA e SHA256 puros."""

import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "RSA"))
sys.path.insert(0, str(_HERE.parent / "Sha256"))

from rsa_impl import (
    generate_keypair,
    encrypt,
    decrypt,
    sign,
    verify,
    key_to_dict,
    key_from_dict,
)

try:
    import requests
except ImportError:
    print("ERRO: instale requests com:  pip install requests")
    sys.exit(1)

SERVER = "http://localhost:5000"
POLL_INTERVAL = 2


def _post(path: str, payload: dict) -> dict:
    r = requests.post(f"{SERVER}{path}", json=payload, timeout=5)
    r.raise_for_status()
    return r.json()


def _get(path: str) -> dict:
    r = requests.get(f"{SERVER}{path}", timeout=5)
    r.raise_for_status()
    return r.json()


def register(username: str, pub_key: tuple):
    """Registra o usuario e sua chave publica no servidor."""
    return _post("/register", {
        "username": username,
        "public_key": key_to_dict(pub_key),
    })


def get_pubkey(username: str) -> tuple:
    """Busca a chave publica de outro usuario no servidor."""
    data = _get(f"/keys/{username}")
    return key_from_dict(data["public_key"])


def send(sender: str, recipient: str, message: str,
         recipient_pub: tuple, sender_priv: tuple):
    """Cifra a mensagem com a chave publica do destinatario e assina com a chave privada do remetente."""
    blocks = encrypt(message, recipient_pub)
    signature = sign(message, sender_priv)
    return _post("/webhook/message", {
        "from":      sender,
        "to":        recipient,
        "blocks":    blocks,
        "signature": signature,
    })


def fetch(username: str) -> list:
    """Busca e limpa as mensagens pendentes do usuario."""
    return _get(f"/messages/{username}").get("messages", [])


def list_users() -> list:
    """Lista todos os usuarios registrados no servidor."""
    return _get("/users").get("users", [])


def _polling_thread(username: str, priv_key: tuple, stop: threading.Event):
    """Verifica novas mensagens a cada 2 segundos, decifra e valida a assinatura."""
    while not stop.is_set():
        try:
            messages = fetch(username)
            for m in messages:
                sender    = m["from"]
                blocks    = m["blocks"]
                signature = m["signature"]
                ts        = m.get("timestamp", "")

                try:
                    plaintext  = decrypt(blocks, priv_key)
                    sender_pub = get_pubkey(sender)
                    valid      = verify(plaintext, signature, sender_pub)
                    auth_tag   = "[assinatura OK]" if valid else "[ASSINATURA INVALIDA!]"
                    print(f"\n  {ts} | {sender}: {plaintext}  {auth_tag}")
                except Exception as e:
                    print(f"\n  [ERRO ao processar msg de {sender}]: {e}")

                print(f"[{username}] ", end="", flush=True)
        except Exception:
            pass
        stop.wait(POLL_INTERVAL)


def main():
    print("=" * 60)
    print("Chat E2E com RSA -- Cliente Terminal")
    print("Criptografia Ponta a Ponta (RSA + SHA256 puros)")
    print("=" * 60)

    if len(sys.argv) > 1:
        username = sys.argv[1].strip()
        print(f"Usuario: {username}")
    else:
        username = input("Seu nome de usuario: ").strip()
    if not username:
        print("Nome invalido.")
        sys.exit(1)

    print(f"\nGerando par de chaves RSA 512 bits para '{username}'...")
    print("(pode levar alguns segundos na primeira vez)\n")
    pub_key, priv_key = generate_keypair(bits=512)
    e, n = pub_key
    print(f"  Chave publica: e={e}, n={str(n)[:30]}...")

    try:
        register(username, pub_key)
        print(f"  Registrado no servidor como '{username}'.\n")
    except requests.exceptions.ConnectionError:
        print("\nERRO: Servidor nao encontrado em http://localhost:5000")
        print("      Inicie o servidor com:  python chat_server.py")
        sys.exit(1)
    except Exception as e:
        print(f"\nERRO ao registrar: {e}")
        sys.exit(1)

    stop_event = threading.Event()
    poller = threading.Thread(
        target=_polling_thread,
        args=(username, priv_key, stop_event),
        daemon=True,
    )
    poller.start()

    print("Comandos disponiveis:")
    print("  <destinatario>: <mensagem>  -- enviar mensagem cifrada")
    print("  /usuarios                   -- listar usuarios online")
    print("  /sair                       -- sair do chat")
    print()

    try:
        while True:
            try:
                line = input(f"[{username}] ")
            except (EOFError, KeyboardInterrupt):
                break

            line = line.strip()
            if not line:
                continue

            if line == "/sair":
                break

            if line == "/usuarios":
                try:
                    users = list_users()
                    print(f"  Usuarios online: {', '.join(users) or '(nenhum)'}")
                except Exception as e:
                    print(f"  Erro: {e}")
                continue

            if ":" not in line:
                print("  Formato: <destinatario>: <mensagem>")
                continue

            recipient, _, message = line.partition(":")
            recipient = recipient.strip()
            message   = message.strip()

            if not recipient or not message:
                print("  Destinatario ou mensagem vazia.")
                continue

            try:
                recipient_pub = get_pubkey(recipient)
                send(username, recipient, message, recipient_pub, priv_key)
                print(f"  Enviado para '{recipient}' (cifrado com RSA + assinado com SHA256)")
            except requests.exceptions.HTTPError as e:
                print(f"  Erro HTTP: {e.response.json().get('error', e)}")
            except Exception as e:
                print(f"  Erro ao enviar: {e}")

    finally:
        stop_event.set()
        print("\nSaindo do chat.")


if __name__ == "__main__":
    main()
