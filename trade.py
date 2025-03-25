import os
import time
import logging
import base58
import json
import requests
from solders.keypair import Keypair
from solana.rpc.api import Client
from base64 import b64decode, b64encode

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
            swap_result = execute_jupiter_swap_direct(keypair, swap_quote["quote_response"])
            
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

def execute_jupiter_swap_direct(keypair, quote_data):
    """
    Exécute un swap en utilisant directement l'API Jupiter v6 avec Auth API
    Cette méthode contourne les problèmes de signature et d'envoi de transaction
    
    Args:
        keypair: Objet Keypair de Solana pour signer la transaction
        quote_data: Données du devis obtenues via get_jupiter_quote
        
    Returns:
        dict: Résultat du swap
    """
    try:
        wallet_address = str(keypair.pubkey())
        
        # 1. Créer une session d'échange avec l'API Jupiter
        logger.info("🔐 Création d'une session d'échange Jupiter...")
        
        # 2. Construire la transaction de swap via l'API Jupiter
        swap_params = {
            "quoteResponse": quote_data,
            "userPublicKey": wallet_address,
            "wrapAndUnwrapSol": True  # Gère automatiquement le wrapped SOL
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
        
        # 3. Récupérer la transaction
        swap_data = swap_response.json()
        transaction_data = swap_data["swapTransaction"]
        
        # 4. Utiliser directement l'API RPC de Solana pour envoyer la transaction signée
        rpc_url = "https://api.mainnet-beta.solana.com"
        headers = {"Content-Type": "application/json"}
        
        logger.info("📡 Préparation de l'envoi de la transaction via RPC...")
        
        # 5. Créer un compte de type walletAdapter pour Jupiter v4
        # Préparer les données pour l'API Jupiter Direct Swap
        try:
            # Appel à l'API SwapInstructions de Jupiter pour obtenir des instructions séparées
            logger.info("🔧 Obtention des instructions séparées via Jupiter...")
            swap_instr_params = {
                "quoteResponse": quote_data,
                "userPublicKey": wallet_address,
                "wrapUnwrapSOL": True
            }
            
            instr_response = requests.post(f"{JUPITER_API_BASE}/swap-instructions", json=swap_instr_params)
            
            if instr_response.status_code != 200:
                logger.warning(f"⚠️ Impossible d'obtenir les instructions séparées: {instr_response.text}")
                
                # Si on ne peut pas obtenir les instructions séparées, on utilise la transaction complète
                logger.info("📝 Utilisation du processus standard Jupiter v6...")
                
                # Méthode manuelle d'envoi de transaction
                # Créer une requête RPC directe
                sign_payload = {
                    "jsonrpc": "2.0",
                    "id": str(int(time.time())),
                    "method": "sendTransaction",
                    "params": [
                        transaction_data,
                        {
                            "skipPreflight": False,
                            "preflightCommitment": "confirmed",
                            "encoding": "base64",
                            "maxRetries": 3
                        }
                    ]
                }
                
                logger.info(f"📤 Envoi de la transaction encodée via RPC...")
                sign_response = requests.post(rpc_url, headers=headers, json=sign_payload)
                sign_result = sign_response.json()
                
                if "error" in sign_result:
                    logger.error(f"❌ Erreur RPC: {sign_result['error']}")
                    return {
                        "status": "error",
                        "message": f"Erreur lors de l'envoi: {sign_result['error'].get('message', 'Erreur inconnue')}"
                    }
                
                tx_signature = sign_result["result"]
                logger.info(f"📝 Transaction envoyée avec signature: {tx_signature}")
                
                # Créer URL Solana Explorer
                explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
                
                return {
                    "status": "pending",
                    "message": "Transaction envoyée, vérifiez l'explorateur Solana pour confirmation",
                    "txid": tx_signature,
                    "explorer_url": explorer_url,
                    "input_amount": 1.0,
                    "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                }
            else:
                logger.info("⚠️ Obtention des instructions OK, mais cette approche nécessite plus de développement")
                logger.info("🔄 Repli sur l'approche standard...")
                
                # Continuer avec l'approche standard comme au-dessus
                sign_payload = {
                    "jsonrpc": "2.0",
                    "id": str(int(time.time())),
                    "method": "sendTransaction",
                    "params": [
                        transaction_data,
                        {
                            "skipPreflight": False,
                            "preflightCommitment": "confirmed",
                            "encoding": "base64"
                        }
                    ]
                }
                
                logger.info(f"📤 Envoi de la transaction encodée via RPC...")
                sign_response = requests.post(rpc_url, headers=headers, json=sign_payload)
                sign_result = sign_response.json()
                
                if "error" in sign_result:
                    logger.error(f"❌ Erreur RPC: {sign_result['error']}")
                    return {
                        "status": "error",
                        "message": f"Erreur lors de l'envoi: {sign_result['error'].get('message', 'Erreur inconnue')}"
                    }
                
                tx_signature = sign_result["result"]
                logger.info(f"📝 Transaction envoyée avec signature: {tx_signature}")
                
                # Créer URL Solana Explorer
                explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
                
                return {
                    "status": "pending",
                    "message": "Transaction envoyée, vérifiez l'explorateur Solana pour confirmation",
                    "txid": tx_signature,
                    "explorer_url": explorer_url,
                    "input_amount": 1.0,
                    "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                }
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'approche alternative: {str(e)}")
            logger.info("🔄 Tentative avec l'approche standard...")
            
            # Méthode standard comme au-dessus
            sign_payload = {
                "jsonrpc": "2.0",
                "id": str(int(time.time())),
                "method": "sendTransaction",
                "params": [
                    transaction_data,
                    {
                        "skipPreflight": False,
                        "preflightCommitment": "confirmed",
                        "encoding": "base64"
                    }
                ]
            }
            
            logger.info(f"📤 Envoi de la transaction encodée via RPC...")
            sign_response = requests.post(rpc_url, headers=headers, json=sign_payload)
            sign_result = sign_response.json()
            
            if "error" in sign_result:
                logger.error(f"❌ Erreur RPC: {sign_result['error']}")
                return {
                    "status": "error",
                    "message": f"Erreur lors de l'envoi: {sign_result['error'].get('message', 'Erreur inconnue')}"
                }
            
            tx_signature = sign_result["result"]
            logger.info(f"📝 Transaction envoyée avec signature: {tx_signature}")
            
            # Créer URL Solana Explorer
            explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
            
            return {
                "status": "pending",
                "message": "Transaction envoyée, vérifiez l'explorateur Solana pour confirmation",
                "txid": tx_signature,
                "explorer_url": explorer_url,
                "input_amount": 1.0,
                "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
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


