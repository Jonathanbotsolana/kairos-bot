import os
import base58
from flask import Flask, jsonify
from solders.keypair import Keypair
from solders.pubkey import Pubkey

# Récupération de la clé privée Phantom depuis la variable d'environnement
phantom_key_base58 = os.environ.get("PHANTOM_KEY_BASE58")

if not phantom_key_base58:
    raise ValueError("❌ Clé privée PHANTOM non trouvée dans l'environnement")

# Décodage et création du keypair
decoded_key = base58.b58decode(phantom_key_base58)
if len(decoded_key) == 32:
    keypair = Keypair.from_seed(decoded_key)
elif len(decoded_key) == 64:
    keypair = Keypair.from_bytes(decoded_key)
else:
    raise ValueError("❌ Format de clé non reconnu (doit être 32 ou 64 bytes)")

# Initialisation de l'application Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "🧠 Kairos bot is alive and running!"

@app.route("/status")
def status():
    return jsonify({
        "bot": "Kairos",
        "network": "mainnet-beta",
        "status": "active",
        "wallet": str(keypair.pubkey())
    })

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=10000)


