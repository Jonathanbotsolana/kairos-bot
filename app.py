import os
import base58
import subprocess
from flask import Flask, jsonify
from solders.keypair import Keypair

# Nom unifié de la variable d'environnement
PHANTOM_KEY_ENV = "PHANTOM_KEY_BASE58"

# Récupération de la clé privée Phantom depuis la variable d'environnement
phantom_key_base58 = os.environ.get(PHANTOM_KEY_ENV)

if not phantom_key_base58:
    raise ValueError(f"❌ Clé privée {PHANTOM_KEY_ENV} non trouvée dans l'environnement")

# Décodage et création du keypair
try:
    decoded_key = base58.b58decode(phantom_key_base58)
    if len(decoded_key) == 32:
        keypair = Keypair.from_seed(decoded_key)
    elif len(decoded_key) == 64:
        keypair = Keypair.from_bytes(decoded_key)
    else:
        raise ValueError("❌ Format de clé non reconnu (doit être 32 ou 64 bytes)")
    
    wallet_address = str(keypair.pubkey())
    print(f"✅ Wallet chargé : {wallet_address}")
except Exception as e:
    raise RuntimeError(f"❌ Erreur lors du décodage de la clé : {str(e)}")

# Initialisation de l'application Flask
app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({
        "message": "🧠 Kairos bot is alive and running!",
        "wallet": wallet_address
    })

@app.route("/status")
def status():
    return jsonify({
        "bot": "Kairos",
        "network": "mainnet-beta",
        "status": "active",
        "wallet": wallet_address
    })

@app.route("/debug")
def debug():
    """Route temporaire pour déboguer le déploiement"""
    return jsonify({
        "pwd": os.getcwd(),
        "files": os.listdir(),
        "env_vars": list(os.environ.keys()),
        "python_version": subprocess.check_output(["python", "--version"]).decode().strip()
    })

@app.route("/trade")
def trigger_trade():
    try:
        print("🚀 Lancement manuel du trading")
        
        # Vérifier si le fichier trade.py existe
        if os.path.exists("trade.py"):
            result = subprocess.run(["python", "trade.py"], capture_output=True, text=True)
            print(f"📊 Résultat: stdout={result.stdout}, stderr={result.stderr}")
            
            return jsonify({
                "status": "Trade executed manually",
                "stdout": result.stdout,
                "stderr": result.stderr
            })
        else:
            # Si pas de fichier trade.py, on exécute directement la fonction main de trade
            from trade_logic import main as trade_main
            result = trade_main(keypair)
            return jsonify({
                "status": "Trade executed directly",
                "result": result
            })
            
    except Exception as e:
        print(f"❌ Erreur: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🚀 Démarrage du serveur Kairos")
    app.run(debug=False, host="0.0.0.0", port=10000)

