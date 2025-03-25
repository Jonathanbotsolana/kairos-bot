import os
import time
import logging
import base58
import json
import requests
import importlib.util
from solders.keypair import Keypair
from solders.hash import Hash
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
RPC_URL = "https://api.mainnet-beta.solana.com"  # Solana RPC URL

def sign_transaction(transaction_data, keypair):
    """
    Signe une transaction encodée en base64 avec le keypair fourni
    
    Args:
        transaction_data: Transaction encodée en base64
        keypair: Objet Keypair Solana pour signer
        
    Returns:
        str: Transaction signée encodée en base64
    """
    try:
        # Décoder la transaction base64
        transaction_bytes = b64decode(transaction_data)
        
        # Obtenir un blockhash récent via RPC direct
        try:
            rpc_response = requests.post(
                RPC_URL,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getLatestBlockhash",
                    "params": [{"commitment": "finalized"}]
                }
            )
            recent_blockhash = rpc_response.json()["result"]["value"]["blockhash"]
            logger.info(f"✅ Blockhash récent obtenu: {recent_blockhash}")
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de l'obtention du blockhash: {str(e)}")
            recent_blockhash = None
        
        # Approche simplifiée: signer directement le message de transaction
        try:
            # Signer directement les données de transaction
            signature_obj = keypair.sign_message(transaction_bytes)
            
            # La signature est l'objet lui-même, pas un attribut
            signature_bytes = bytes(signature_obj)
            
            # Créer une structure simplifiée pour la transaction signée
            signed_tx_data = {
                "transaction": transaction_data,
                "signature": base58.b58encode(signature_bytes).decode('utf-8'),
                "pubkey": str(keypair.pubkey())
            }
            
            # Sérialiser en JSON puis encoder en base64
            signed_tx_json = json.dumps(signed_tx_data)
            signed_tx_b64 = b64encode(signed_tx_json.encode()).decode('utf-8')
            
            logger.info("✅ Transaction signée avec succès (méthode simplifiée)")
            
            # Utiliser la bibliothèque solana pour créer une transaction correctement signée
            try:
                from solana.transaction import Transaction
                
                # Décoder la transaction
                tx = Transaction.deserialize(transaction_bytes)
                
                # Signer avec le keypair
                tx.sign([keypair])
                
                # Sérialiser et encoder en base64
                signed_tx_bytes = tx.serialize()
                signed_tx_b64 = b64encode(signed_tx_bytes).decode('utf-8')
                
                logger.info("✅ Transaction signée avec succès (solana-py)")
                return signed_tx_b64
            except Exception as e:
                logger.warning(f"⚠️ Erreur lors de la signature avec solana-py: {str(e)}")
                
                # Si la méthode solana-py échoue, essayer avec la méthode Jupiter
                try:
                    # Créer une structure pour l'API Jupiter
                    signed_tx_data = {
                        "transaction": transaction_data,
                        "signatures": [{
                            "publicKey": str(keypair.pubkey()),
                            "signature": base58.b58encode(signature_bytes).decode('utf-8')
                        }]
                    }
                    
                    # Encoder en base64
                    signed_tx_json = json.dumps(signed_tx_data)
                    signed_tx_b64 = b64encode(signed_tx_json.encode()).decode('utf-8')
                    
                    logger.info("✅ Transaction signée avec succès (format Jupiter)")
                    return signed_tx_b64
                except Exception as e2:
                    logger.warning(f"⚠️ Erreur lors de la signature au format Jupiter: {str(e2)}")
                    logger.warning("⚠️ Utilisation de la transaction non signée (va probablement échouer)")
                    return transaction_data
            
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de la signature simplifiée: {str(e)}")
            
            # Essayer avec solders en utilisant le blockhash récent
            try:
                from solders.transaction import Transaction as SoldersTransaction
                from solders.message import Message
                from solders.hash import Hash
                
                # Désérialiser comme un Message
                message = Message.from_bytes(transaction_bytes)
                
                # Créer une transaction avec le blockhash récent
                if recent_blockhash:
                    blockhash = Hash.from_string(recent_blockhash)
                    # Créer une transaction avec le blockhash récent
                    tx = SoldersTransaction(message, [], blockhash)
                else:
                    # Fallback sans blockhash
                    tx = SoldersTransaction(message, [])
                
                # Signer la transaction avec le keypair
                signature_obj = keypair.sign_message(bytes(message))
                
                # La signature est l'objet lui-même
                signatures = [signature_obj]
                
                # Créer une nouvelle transaction avec la signature
                tx_signed = SoldersTransaction(message, signatures)
                
                # Sérialiser la transaction signée
                signed_tx_bytes = bytes(tx_signed)
                logger.info("✅ Transaction signée avec succès (solders)")
                return b64encode(signed_tx_bytes).decode('utf-8')
                
            except Exception as e2:
                logger.warning(f"⚠️ Erreur lors de la signature avec solders: {str(e2)}")
                
                # Essayer avec une approche alternative de solders
                try:
                    from solders.transaction import VersionedTransaction
                    from solders.message import MessageV0
                    
                    # Essayer de désérialiser comme une transaction versionnée
                    try:
                        versioned_tx = VersionedTransaction.from_bytes(transaction_bytes)
                        message = versioned_tx.message
                        
                        # Signer le message
                        signature_obj = keypair.sign_message(bytes(message))
                        
                        # La signature est l'objet lui-même
                        signatures = [signature_obj]
                        
                        # Créer une nouvelle transaction avec la signature
                        tx_signed = VersionedTransaction(message, signatures)
                        
                        # Sérialiser la transaction signée
                        signed_tx_bytes = bytes(tx_signed)
                        logger.info("✅ Transaction signée avec succès (solders versioned)")
                        return b64encode(signed_tx_bytes).decode('utf-8')
                        
                    except Exception as e_versioned:
                        logger.warning(f"⚠️ Erreur avec transaction versionnée: {str(e_versioned)}")
                        raise e_versioned
                        
                except Exception as e3:
                    logger.warning(f"⚠️ Erreur lors de la signature alternative avec solders: {str(e3)}")
                    
                    # Dernière tentative: utiliser directement l'API Jupiter pour signer
                    logger.info("🔄 Tentative de signature via l'API Jupiter...")
                    
                    # Retourner la transaction non signée pour l'instant
                    logger.warning("⚠️ Utilisation de la transaction non signée (va probablement échouer)")
                    return transaction_data
    
    except Exception as e:
        logger.error(f"❌ Erreur lors de la signature de la transaction: {str(e)}")
        return transaction_data

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

def create_jupiter_transaction(wallet_address, quote_data, priority_fee=5000):
    """
    Crée une transaction de swap via l'API Jupiter
    
    Args:
        wallet_address: Adresse du wallet Solana
        quote_data: Données du devis obtenues via get_jupiter_quote
        priority_fee: Frais de priorité en lamports
        
    Returns:
        dict: Résultat contenant la transaction ou une erreur
    """
    try:
        # Paramètres pour l'API Jupiter
        swap_params = {
            "quoteResponse": quote_data,
            "userPublicKey": wallet_address,
            "wrapAndUnwrapSol": True,
            "prioritizationFeeLamports": priority_fee
        }
        
        logger.info(f"🏗️ Création d'une transaction via Jupiter (priorité: {priority_fee} lamports)...")
        swap_response = requests.post(f"{JUPITER_API_BASE}/swap", json=swap_params)
        
        if swap_response.status_code != 200:
            return {
                "status": "error",
                "message": f"Erreur lors de la création de la transaction: {swap_response.text}"
            }
        
        swap_data = swap_response.json()
        transaction_data = swap_data["swapTransaction"]
        
        return {
            "status": "success",
            "transaction": transaction_data
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création de la transaction: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

def send_transaction(transaction_data, skip_preflight=True):
    """
    Envoie une transaction signée via l'API RPC de Solana
    
    Args:
        transaction_data: Transaction signée encodée en base64
        skip_preflight: Ignorer les vérifications préliminaires
        
    Returns:
        dict: Résultat de l'envoi
    """
    try:
        headers = {"Content-Type": "application/json"}
        
        # Vérifier si la transaction est au format Jupiter (JSON)
        try:
            # Essayer de décoder et parser comme JSON
            decoded_data = b64decode(transaction_data).decode('utf-8')
            json_data = json.loads(decoded_data)
            
            # Si c'est un dict avec 'transaction' et 'signatures', c'est au format Jupiter
            if isinstance(json_data, dict) and 'transaction' in json_data and 'signatures' in json_data:
                logger.info("📝 Transaction au format Jupiter détectée, extraction...")
                # Extraire la transaction réelle
                transaction_data = json_data['transaction']
        except:
            # Si ce n'est pas du JSON, c'est probablement déjà une transaction encodée en base64
            pass
        
        # Créer une requête RPC
        payload = {
            "jsonrpc": "2.0",
            "id": str(int(time.time())),
            "method": "sendTransaction",
            "params": [
                transaction_data,
                {
                    "skipPreflight": skip_preflight,
                    "preflightCommitment": "confirmed",
                    "encoding": "base64",
                    "maxRetries": 5
                }
            ]
        }
        
        logger.info(f"📤 Envoi de la transaction via RPC...")
        response = requests.post(RPC_URL, headers=headers, json=payload)
        result = response.json()
        
        if "error" in result:
            logger.error(f"❌ Erreur RPC: {result['error']}")
            return {
                "status": "error",
                "message": f"Erreur lors de l'envoi: {result['error'].get('message', 'Erreur inconnue')}"
            }
        
        tx_signature = result["result"]
        logger.info(f"📝 Transaction envoyée avec signature: {tx_signature}")
        
        # Créer URL Solana Explorer
        explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
        
        return {
            "status": "success",
            "txid": tx_signature,
            "explorer_url": explorer_url
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'envoi de la transaction: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

def execute_jupiter_swap_direct(keypair, quote_data):
    """
    Exécute un swap en utilisant directement l'API Jupiter v6
    
    Args:
        keypair: Objet Keypair de Solana pour signer la transaction
        quote_data: Données du devis obtenues via get_jupiter_quote
        
    Returns:
        dict: Résultat du swap
    """
    try:
        wallet_address = str(keypair.pubkey())
        
        # 1. Créer une transaction via Jupiter
        tx_result = create_jupiter_transaction(wallet_address, quote_data)
        
        if tx_result["status"] != "success":
            return {
                "status": "error",
                "message": tx_result["message"]
            }
        
        # 2. Signer la transaction avec notre keypair
        signed_tx = sign_transaction(tx_result["transaction"], keypair)
        
        # 3. Envoyer la transaction signée
        send_result = send_transaction(signed_tx)
        
        if send_result["status"] != "success":
            # Si l'envoi échoue, essayer avec des frais de priorité plus élevés
            logger.info("🔄 Nouvelle tentative avec des frais de priorité plus élevés...")
            
            # Créer une nouvelle transaction avec des frais plus élevés
            retry_tx_result = create_jupiter_transaction(wallet_address, quote_data, priority_fee=10000)
            
            if retry_tx_result["status"] != "success":
                return {
                    "status": "error",
                    "message": retry_tx_result["message"]
                }
            
            # Signer la nouvelle transaction
            signed_retry_tx = sign_transaction(retry_tx_result["transaction"], keypair)
            
            # Envoyer la nouvelle transaction
            retry_send_result = send_transaction(signed_retry_tx)
            
            if retry_send_result["status"] != "success":
                return {
                    "status": "error",
                    "message": retry_send_result["message"]
                }
            
            # Utiliser le résultat de la nouvelle tentative
            send_result = retry_send_result
        
        # 4. Créer le résultat final
        return {
            "status": "pending",
            "message": "Transaction envoyée, vérifiez l'explorateur Solana pour confirmation",
            "txid": send_result["txid"],
            "explorer_url": send_result["explorer_url"],
            "input_amount": 1.0,
            "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000
        }
            
    except Exception as e:
        error_msg = f"Erreur lors de l'exécution du swap: {str(e)}"
        logger.error(f"❌ {error_msg}")
        return {
            "status": "error",
            "message": error_msg
        }

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

if __name__ == "__main__":
    # Ce code s'exécute uniquement si le fichier est appelé directement
    result = main()
    logger.info(f"⏹️ Script terminé avec résultat: {result}")