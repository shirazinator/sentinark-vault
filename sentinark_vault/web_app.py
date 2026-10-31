"""
Sentinark-Vault: Web Application Dashboard (Flask)
Run via: python3 -m sentinark_vault.web_app
"""

from flask import Flask, render_template, request, jsonify
from .auditor import audit_password
from .generator import generate_secure_password, generate_passphrase

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/audit", methods=["POST"])
def api_audit():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Empty password provided"}), 400

    report = audit_password(password, check_breaches=True)
    return jsonify(report)


@app.route("/api/generate", methods=["GET"])
def api_generate():
    kind = request.args.get("type", "complex")
    if kind == "passphrase":
        result = generate_passphrase(num_words=5)
    else:
        length = int(request.args.get("length", 18))
        result = generate_secure_password(length=length)
    return jsonify(result)


def run_server(port=5001, debug=False):
    print(f"\n[*] Starting Sentinark-Vault Web Console on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)


if __name__ == "__main__":
    run_server()
