from flask import Flask, jsonify
import os
import base58
from solana.keypair import Keypair
from solana.rpc.api import Client

app = Flask(__name__)

# === 1. Chargement de la clé Phantom depuis les variables d'environnement ===
secret_key_base58 = os.getenv("PHANTOM_SECRET_KEY")
if not secret_key_base58:
    raise ValueError("❌ PHANTOM_SECRET_KEY non défini dans l'environnement")

try:
    keypair = Keypair.from_secret_key(base58.b58decode(secret_key_base58.strip()))
    public_key = str(keypair.public_key)
except Exception as e:
    raise ValueError(f"❌ Erreur lors de la création du Keypair : {e}")

# === 2. Connexion au mainnet Solana ===
client = Client("https://api.mainnet-beta.solana.com")

@app.route("/")
def home():
    return "Kairos is running."

@app.route("/status")
def status():
    try:
        balance = client.get_balance(keypair.public_key)["result"]["value"] / 1e9
        return jsonify({
            "bot": "Kairos",
            "network": "mainnet-beta",
            "status": "active",
            "wallet": public_key,
            "balance": f"{balance:.5f} SOL"
        })
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

# === Endpoints supplémentaires pour swaps à venir ===
# /swap, /report, etc. (à ajouter après validation du fonctionnement de base)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

