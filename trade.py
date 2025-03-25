import os
import time
import logging
import base58
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.transaction import Transaction
from solana.rpc.types import TxOpts
import requests
from typing import Dict, Any

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kairos-trade")

# Constantes
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC token address on Solana
JUPITER_API_BASE = "https://quote-api.jup.ag/v6"  # Jupiter Aggregator API

def main(keypair=None):
    """
    Fonction principale de la logique de trading
    
    Args:
        keypair: Objet Keypair de Solana (optionnel, peut être passé depuis app.py)
    
    Returns:
        dict: Résultat de l'opération de trading
    """
    logger.info("🚀 Démarrage de la logique de trading Kairos")
    
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
        
        # Exécute le swap de 1 USDC vers SOL
        swap_result = swap_usdc_to_sol(keypair, amount_usdc=1.0)
        
        return {
            "status": "success",
            "wallet": wallet_address,
            "swap_result": swap_result,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'exécution du bot: {str(e)}")
        return {"status": "error", "message": str(e)}

def swap_usdc_to_sol(keypair: Keypair, amount_usdc: float) -> Dict[str, Any]:
    """
    Effectue un swap de USDC vers SOL en utilisant Jupiter Aggregator
    
    Args:
        keypair: Objet Keypair de Solana
        amount_usdc: Montant d'USDC à échanger
    
    Returns:
        Dict: Résultat du swap
    """
    wallet_pubkey = keypair.pubkey()
    wallet_address = str(wallet_pubkey)
    logger.info(f"💱 Préparation du swap de {amount_usdc} USDC vers SOL pour {wallet_address}")

    # Initialiser le client RPC Solana (mainnet)
    client = Client("https://api.mainnet-beta.solana.com")
    
    try:
        # 1. Obtenir un devis (quote) de Jupiter
        amount_in_lamports = int(amount_usdc * 1_000_000)  # USDC a 6 décimales
        
        quote_params = {
            "inputMint": USDC_MINT,
            "outputMint": "So11111111111111111111111111111111111111112",  # Wrapped SOL
            "amount": amount_in_lamports,
            "slippageBps": 50,  # 0.5% de slippage maximum
        }
        
        logger.info("🔍 Obtention du devis de swap via Jupiter...")
        quote_response = requests.get(f"{JUPITER_API_BASE}/quote", params=quote_params)
        if quote_response.status_code != 200:
            logger.error(f"❌ Erreur lors de l'obtention du devis: {quote_response.text}")
            return {"status": "error", "message": f"Erreur API Jupiter: {quote_response.text}"}
        
        quote_data = quote_response.json()
        logger.info(f"✅ Devis obtenu: {amount_usdc} USDC ≈ {float(quote_data['outAmount']) / 1e9:.9f} SOL")
        
        # 2. Construire la transaction de swap
        swap_params = {
            "quoteResponse": quote_data,
            "userPublicKey": wallet_address,
            "wrapUnwrapSOL": True  # Automatiquement unwrap SOL après le swap
        }
        
        logger.info("🏗️ Construction de la transaction de swap...")
        swap_response = requests.post(f"{JUPITER_API_BASE}/swap", json=swap_params)
        if swap_response.status_code != 200:
            logger.error(f"❌ Erreur lors de la construction du swap: {swap_response.text}")
            return {"status": "error", "message": f"Erreur construction transaction: {swap_response.text}"}
        
        # 3. Signer et envoyer la transaction
        swap_data = swap_response.json()
        transaction_data = swap_data["swapTransaction"]
        
        # Décoder la transaction encodée en base64
        from base64 import b64decode
        from solders.transaction import VersionedTransaction
        from solders.message import to_bytes_versioned
        
        serialized_transaction = b64decode(transaction_data)
        transaction = VersionedTransaction.from_bytes(serialized_transaction)
        
        # Signer la transaction
        logger.info("✍️ Signature de la transaction...")
        signatures = [keypair]
        message = to_bytes_versioned(transaction.message)
        signatures_bytes = bytes().join([sig.sign(message) for sig in signatures])
        transaction.signatures = list(signatures_bytes)
        
        # Envoyer la transaction
        logger.info("📤 Envoi de la transaction sur la blockchain...")
        result = client.send_transaction(
            transaction,
            *signatures,
            opts=TxOpts(skip_preflight=False, preflight_commitment="confirmed")
        )
        
        logger.info(f"✅ Transaction soumise avec succès: {result.value}")
        
        # 4. Attendre la confirmation
        logger.info("⏳ Attente de la confirmation...")
        max_retries = 10
        for i in range(max_retries):
            try:
                confirm_result = client.confirm_transaction(result.value)
                if confirm_result.value:
                    logger.info(f"🎉 Transaction confirmée!")
                    return {
                        "status": "success",
                        "txid": result.value,
                        "input_amount": amount_usdc,
                        "output_amount": float(quote_data['outAmount']) / 1e9,
                        "input_token": "USDC",
                        "output_token": "SOL"
                    }
            except Exception as e:
                logger.warning(f"Attente de confirmation, essai {i+1}/{max_retries}...")
            time.sleep(2)
        
        # Si on arrive ici, c'est que la transaction n'a pas été confirmée après plusieurs essais
        logger.warning("⚠️ Transaction soumise mais confirmation non reçue, vérifiez manuellement")
        return {
            "status": "pending",
            "message": "Transaction soumise mais confirmation non reçue",
            "txid": result.value
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du swap: {str(e)}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    # Ce code s'exécute uniquement si le fichier est appelé directement
    result = main()
    logger.info(f"⏹️ Script terminé avec résultat: {result}")


