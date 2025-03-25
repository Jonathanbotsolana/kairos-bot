import os
import time
import logging
import base58
import json
import requests
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solders.transaction import VersionedTransaction  # Utilisation de solders.transaction
from base64 import b64decode

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kairos-trade")

# Constantes
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC token address on Solana
SOL_MINT = "So11111111111111111111111111111111111111112"  # Wrapped SOL address
JUPITER_API_BASE = "https://quote-api.jup.ag/v6"  # Jupiter Aggregator API

def main(keypair=None):
    """
    Fonction principale de la logique de trading - Effectue un swap réel de 1 USDC vers SOL
    
    Args:
        keypair: Objet Keypair de Solana (optionnel, peut être passé depuis app.py)
    
    Returns:
        dict: Résultat de l'opération de trading
    """
    logger.info("🚀 Démarrage du swap réel de 1 USDC vers SOL")
    
    try:
        # Si keypair n'est pas fourni, on tente de le récupérer depuis l'environnement
        if keypair is None:
            phantom_key = os.environ.get("PHANTOM_KEY_BASE58")
            if not phantom_key:
                logger.error("⚠️ Variable d'environnement PHANTOM_KEY_BASE58 manquante")
                return {"status": "error", "message": "Clé manquante"}
            
            decoded = base58.b58decode(phantom_key)
            if len(decoded) == 64:
                keypair = Keypair.from_bytes(decoded)
            elif len(decoded) == 32:
                keypair = Keypair.from_seed(decoded)
            else:
                logger.error("❌ Format de clé incorrect")
                return {"status": "error", "message": "Format de clé incorrect"}
        
        wallet_address = str(keypair.pubkey())
        logger.info(f"✅ Wallet préparé: {wallet_address}")
        
        # Obtenir un devis de swap de 1 USDC vers SOL
        swap_quote = get_jupiter_quote(amount_usdc=1.0)
        
        if swap_quote["status"] == "success":
            logger.info(f"📊 Devis obtenu: 1 USDC ≈ {swap_quote['out_amount']} SOL (Impact prix: {swap_quote['price_impact']})")
            
            # Exécuter le swap réel
            swap_result = execute_jupiter_swap(keypair, swap_quote["quote_response"])
            
            logger.info(f"💱 Résultat du swap: {swap_result}")
            return {
                "status": "success",
                "wallet": wallet_address,
                "swap_result": swap_result,
                "timestamp": time.time()
            }
        else:
            logger.error(f"❌ Erreur lors de l'obtention du devis: {swap_quote['message']}")
            return {
                "status": "error", 
                "message": swap_quote["message"]
            }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'exécution du swap: {str(e)}")
        return {"status": "error", "message": str(e)}

def get_jupiter_quote(amount_usdc=1.0):
    """
    Obtient un devis pour échanger USDC contre SOL via Jupiter
    
    Args:
        amount_usdc: Montant d'USDC à échanger
        
    Returns:
        dict: Résultat du devis
    """
    try:
        # Convertir le montant USDC en lamports (USDC a 6 décimales)
        amount_in_lamports = int(amount_usdc * 1_000_000)
        
        # Paramètres pour l'API Jupiter
        quote_params = {
            "inputMint": USDC_MINT,
            "outputMint": SOL_MINT,
            "amount": amount_in_lamports,
            "slippageBps": 50,  # 0.5% de slippage maximum
        }
        
        logger.info(f"🔍 Obtention du devis pour {amount_usdc} USDC → SOL...")
        response = requests.get(f"{JUPITER_API_BASE}/quote", params=quote_params)
        
        if response.status_code == 200:
            data = response.json()
            
            # Calculer le montant de sortie en SOL (conversion de lamports à SOL)
            out_amount_sol = float(data["outAmount"]) / 1_000_000_000
            
            # Calculer l'impact sur le prix
            price_impact_percent = float(data.get("priceImpactPct", 0)) * 100
            
            return {
                "status": "success",
                "out_amount": out_amount_sol,
                "price_impact": f"{price_impact_percent:.4f}%",
                "quote_response": data
            }
        else:
            logger.error(f"❌ Erreur API Jupiter: {response.status_code} - {response.text}")
            return {
                "status": "error",
                "message": f"Erreur API Jupiter: {response.status_code}"
            }
            
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'obtention du devis: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

def execute_jupiter_swap(keypair, quote_data):
    """
    Exécute un swap réel via Jupiter en utilisant le devis obtenu
    
    Args:
        keypair: Objet Keypair Solana pour signer la transaction
        quote_data: Données du devis obtenues via get_jupiter_quote
        
    Returns:
        dict: Résultat du swap
    """
    try:
        wallet_address = str(keypair.pubkey())
        
        # Initialiser le client RPC Solana (mainnet)
        client = Client("https://api.mainnet-beta.solana.com")
        
        # Construire la transaction de swap
        swap_params = {
            "quoteResponse": quote_data,
            "userPublicKey": wallet_address,
            "wrapUnwrapSOL": True  # Automatiquement unwrap SOL après le swap
        }
        
        logger.info("🏗️ Construction de la transaction de swap...")
        swap_response = requests.post(f"{JUPITER_API_BASE}/swap", json=swap_params)
        
        if swap_response.status_code != 200:
            error_msg = f"Erreur construction transaction: {swap_response.text}"
            logger.error(f"❌ {error_msg}")
            return {
                "status": "error",
                "message": error_msg
            }
        
        # Récupérer et décoder la transaction
        swap_data = swap_response.json()
        transaction_data = swap_data["swapTransaction"]
        
        # Décoder la transaction encodée en base64
        serialized_transaction = b64decode(transaction_data)
        
        # Utiliser VersionedTransaction de solders pour désérialiser
        transaction = VersionedTransaction.from_bytes(serialized_transaction)
        
        # Signer et envoyer la transaction
        logger.info("✍️ Signature et envoi de la transaction...")
        result = client.send_transaction(transaction, keypair)
        
        tx_signature = result.value
        logger.info(f"📝 Transaction envoyée avec signature: {tx_signature}")
        
        # Créer URL Solana Explorer pour faciliter la vérification
        explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
        
        # Vérifier le statut de la transaction (avec quelques tentatives)
        max_retries = 5
        transaction_confirmed = False
        
        for i in range(max_retries):
            try:
                time.sleep(2)  # Attendre 2 secondes entre chaque vérification
                logger.info(f"⏳ Vérification de la confirmation, essai {i+1}/{max_retries}...")
                confirm_result = client.confirm_transaction(tx_signature)
                
                if confirm_result.value:
                    transaction_confirmed = True
                    logger.info(f"🎉 Transaction confirmée!")
                    break
            except Exception as e:
                logger.warning(f"Attente de confirmation, erreur: {str(e)}")
        
        # Résultat final selon l'état de la confirmation
        if transaction_confirmed:
            return {
                "status": "success",
                "message": "Swap exécuté avec succès",
                "txid": tx_signature,
                "explorer_url": explorer_url,
                "input_amount": 1.0,
                "input_token": "USDC",
                "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                "output_token": "SOL"
            }
        else:
            logger.warning("⚠️ Transaction envoyée mais pas encore confirmée")
            return {
                "status": "pending",
                "message": "Transaction envoyée mais pas encore confirmée",
                "txid": tx_signature,
                "explorer_url": explorer_url,
                "input_amount": 1.0,
                "input_token": "USDC",
                "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                "output_token": "SOL"
            }
        
    except Exception as e:
        error_msg = f"Erreur lors de l'exécution du swap: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "status": "error",
            "message": error_msg
        }

if __name__ == "__main__":
    # Ce code s'exécute uniquement si le fichier est appelé directement
    result = main()
    logger.info(f"⏹️ Script terminé avec résultat: {result}")


