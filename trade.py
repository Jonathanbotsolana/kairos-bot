import os
import base58
import subprocess
from flask import Flask, jsonify
from solders.keypair import Keypair

# === Chargement de la clé Phantom depuis Render ===
phantom_base58 = os.getenv("PHANTOM_PRIVATE_KEY_BASE58")

if not phantom_base58:
    raise ValueError("⚠️ Variable d'environnement PHANTOM_PRIVATE_KEY_BASE58 manquante")

try:
    decoded = base58.b58decode(phantom_base58)
    if len(decoded) == 64:
        keypair = Keypair.from_bytes(decoded)
    elif len(decoded) == 32:
        raise ValueError("❌ Clé Phantom trop courte : 32 bytes. Exporte-la depuis Phantom, pas depuis seed.")
    else:
        raise ValueError("❌ Format de clé non reconnu (ni 32 ni 64 bytes)")
except Exception as e:
    raise RuntimeError(f"❌ Erreur de décodage de la clé Phantom : {e}")

wallet_address = str(keypair.pubkey())
print(f"✅ Wallet chargé : {wallet_address}")

# === Initialisation du serveur Flask ===
app = Flask(__name__)

@app.route("/")
def status():
    return jsonify({
        "bot": "Kairos",
        "network": "mainnet-beta",
        "status": "active",
        "wallet": wallet_address
    })

@app.route("/trade", methods=["GET"])
def trigger_trade():
    try:
        print("🚀 Lancement manuel de trade.py via /trade")
        result = subprocess.run(["python", "trade.py"], capture_output=True, text=True)
        return jsonify({
            "status": "Trade executed manually",
            "stdout": result.stdout,
            "stderr": result.stderr
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🎯 Lancement automatique de trade.py au démarrage")
    subprocess.Popen(["python", "trade.py"])
    app.run(host="0.0.0.0", port=10000)

