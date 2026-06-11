import sys
import threading
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

_lock = threading.Lock()
_users: dict[str, dict] = {}
_mailboxes: dict[str, list] = {}


def log(msg):
    """Escreve no stderr."""
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


@app.route("/register", methods=["POST"])
def register():
    """Registra um usuário com sua chave pública RSA."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    pub_key = data.get("public_key")

    if not username:
        return jsonify({"error": "campo 'username' é obrigatório"}), 400
    if not pub_key or "exp" not in pub_key or "mod" not in pub_key:
        return jsonify({"error": "campo 'public_key' deve conter 'exp' e 'mod'"}), 400

    with _lock:
        _users[username] = pub_key
        _mailboxes.setdefault(username, [])

    log(f"[REGISTER] {username} registrado.")
    return jsonify({"status": "ok", "username": username})


@app.route("/keys/<username>", methods=["GET"])
def get_key(username):
    """Retorna a chave pública de um usuário."""
    with _lock:
        if username not in _users:
            return jsonify({"error": f"usuário '{username}' não encontrado"}), 404
        return jsonify({"username": username, "public_key": _users[username]})


@app.route("/users", methods=["GET"])
def list_users():
    """Lista todos os usuários registrados."""
    with _lock:
        return jsonify({"users": list(_users.keys())})


@app.route("/webhook/message", methods=["POST"])
def webhook_message():
    """Recebe mensagem cifrada e entrega ao destinatário."""
    data = request.get_json(silent=True) or {}
    sender    = (data.get("from") or "").strip()
    recipient = (data.get("to")   or "").strip()
    blocks    = data.get("blocks")
    signature = data.get("signature")

    if not sender or not recipient:
        return jsonify({"error": "campos 'from' e 'to' são obrigatórios"}), 400
    if not isinstance(blocks, list) or not blocks:
        return jsonify({"error": "campo 'blocks' deve ser lista não-vazia"}), 400
    if signature is None:
        return jsonify({"error": "campo 'signature' é obrigatório"}), 400

    with _lock:
        if sender not in _users:
            return jsonify({"error": f"remetente '{sender}' não registrado"}), 404
        if recipient not in _users:
            return jsonify({"error": f"destinatário '{recipient}' não registrado"}), 404

        _mailboxes[recipient].append({
            "from":      sender,
            "blocks":    blocks,
            "signature": signature,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })

    log(f"[WEBHOOK] {sender} -> {recipient} ({len(blocks)} bloco(s))")
    return jsonify({"status": "entregue", "to": recipient})


@app.route("/messages/<username>", methods=["GET"])
def get_messages(username):
    """Retorna e limpa a caixa de mensagens do usuário."""
    with _lock:
        if username not in _users:
            return jsonify({"error": f"usuário '{username}' não registrado"}), 404
        msgs = _mailboxes.get(username, [])
        _mailboxes[username] = []
    return jsonify({"messages": msgs})


@app.route("/status", methods=["GET"])
def status():
    """Retorna o status do servidor."""
    with _lock:
        return jsonify({
            "status": "online",
            "usuarios": len(_users),
            "mensagens_pendentes": sum(len(v) for v in _mailboxes.values()),
        })


if __name__ == "__main__":
    print("=" * 55)
    print("Chat E2E RSA -- Servidor Webhook")
    print("=" * 55)
    print("Endereco : http://localhost:5000")
    print("Inicie os clientes em outros terminais.")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False)
