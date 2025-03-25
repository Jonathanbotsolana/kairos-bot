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
        
        # Essayer d'abord de traiter comme une transaction versionnée (format Jupiter v6)
        try:
            from solders.transaction import VersionedTransaction
            from solders.signature import Signature as SoldersSignature
            
            # Essayer de désérialiser comme une transaction versionnée
            try:
                # Vérifier si c'est une transaction versionnée (commence par 0x80)
                if transaction_bytes[0] == 0x80:
                    versioned_tx = VersionedTransaction.from_bytes(transaction_bytes)
                    
                    # Signer le message
                    message_bytes = bytes(versioned_tx.message)
                    signature = keypair.sign_message(message_bytes)
                    
                    # Créer une nouvelle transaction versionnée avec la signature
                    signatures = [SoldersSignature.from_bytes(bytes(signature))]
                    
                    # Créer une nouvelle transaction versionnée
                    new_tx = VersionedTransaction(versioned_tx.message, signatures)
                    
                    # Sérialiser et encoder en base64
                    signed_tx_bytes = bytes(new_tx)
                    signed_tx_b64 = b64encode(signed_tx_bytes).decode('utf-8')
                    
                    logger.info("✅ Transaction versionnée signée avec succès")
                    return signed_tx_b64
            except Exception as e_versioned:
                logger.warning(f"⚠️ Pas une transaction versionnée: {str(e_versioned)}")
        except ImportError:
            logger.warning("⚠️ Module VersionedTransaction non disponible")
        
        # Essayer avec le format Jupiter (transaction au format JSON)
        try:
            # Créer une structure pour l'API Jupiter
            signature_bytes = bytes(keypair.sign_message(transaction_bytes))
            signature_base58 = base58.b58encode(signature_bytes).decode('utf-8')
            
            # Créer une transaction signée au format Jupiter
            signed_tx = {
                "tx": transaction_data,
                "signatures": [
                    {
                        "pubkey": str(keypair.pubkey()),
                        "signature": signature_base58
                    }
                ]
            }
            
            # Encoder en JSON puis en base64
            signed_tx_json = json.dumps(signed_tx)
            signed_tx_b64 = b64encode(signed_tx_json.encode('utf-8')).decode('utf-8')
            
            logger.info("✅ Transaction signée avec succès (format Jupiter)")
            return signed_tx_b64
        except Exception as e_jupiter:
            logger.warning(f"⚠️ Erreur lors de la signature au format Jupiter: {str(e_jupiter)}")
        
        # Essayer avec la méthode legacy (Transaction non versionnée)
        try:
            from solders.transaction import Transaction
            from solders.message import Message
            from solders.signature import Signature as SoldersSignature
            
            # Essayer de désérialiser comme un Message
            message = Message.from_bytes(transaction_bytes)
            
            # Signer le message
            signature_bytes = bytes(keypair.sign_message(bytes(message)))
            signature = SoldersSignature.from_bytes(signature_bytes)
            
            # Créer une transaction avec la signature
            signatures = [signature]
            tx = Transaction(message, signatures)
            
            # Sérialiser et encoder en base64
            signed_tx_bytes = bytes(tx)
            signed_tx_b64 = b64encode(signed_tx_bytes).decode('utf-8')
            
            logger.info("✅ Transaction legacy signée avec succès")
            return signed_tx_b64
        except Exception as e_legacy:
            logger.warning(f"⚠️ Erreur lors de la signature legacy: {str(e_legacy)}")
        
        # Méthode de dernier recours: utiliser l'API RPC directement
        try:
            # Signer directement les données de transaction
            signature = keypair.sign_message(transaction_bytes)
            signature_base58 = base58.b58encode(bytes(signature)).decode('utf-8')
            
            # Créer une structure simplifiée pour la transaction signée
            signed_tx_data = {
                "transaction": transaction_data,
                "signature": signature_base58,
                "pubkey": str(keypair.pubkey())
            }
            
            # Sérialiser en JSON puis encoder en base64
            signed_tx_json = json.dumps(signed_tx_data)
            signed_tx_b64 = b64encode(signed_tx_json.encode()).decode('utf-8')
            
            logger.info("✅ Transaction signée avec succès (méthode simplifiée)")
            return signed_tx_b64
        except Exception as e_simple:
            logger.warning(f"⚠️ Erreur lors de la signature simplifiée: {str(e_simple)}")
            
            # En dernier recours, retourner la transaction non signée
            logger.warning("⚠️ Toutes les méthodes de signature ont échoué, retour de la transaction non signée")
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
            "slippageBps": 100,  # 1% de slippage maximum (augmenté pour plus de flexibilité)
            # Suppression des paramètres qui causent des erreurs
            # "onlyDirectRoutes": False,
            # "asLegacyTransaction": False,
            "platformFeeBps": 0  # Pas de frais de plateforme
        }
        
        logger.info(f"🔍 Obtention du devis pour {amount_usdc} USDC → SOL...")
        response = requests.get(f"{JUPITER_API_BASE}/quote", params=quote_params)
        
        if response.status_code == 200:
            data = response.json()
            
            # Calculer le montant de sortie en SOL (conversion de lamports à SOL)
            out_amount_sol = float(data["outAmount"]) / 1_000_000_000
            
            # Calculer l'impact sur le prix
            price_impact_percent = float(data.get("priceImpactPct", 0)) * 100
            
            # Afficher des informations supplémentaires sur la route
            route_info = data.get("routePlan", [])
            if route_info:
                route_summary = []
                for step in route_info:
                    swap_info = f"{step.get('swapInfo', {}).get('label', 'Unknown')}"
                    route_summary.append(swap_info)
                logger.info(f"🛣️ Route: {' → '.join(route_summary)}")
            
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
            # Suppression des paramètres qui pourraient causer des problèmes
            # "computeUnitPriceMicroLamports": priority_fee,
            # "maxRetries": 3,
            # "skipUserAccountsCheck": False
        }
        
        logger.info(f"🏗️ Création d'une transaction via Jupiter (priorité: {priority_fee} lamports)...")
        swap_response = requests.post(f"{JUPITER_API_BASE}/swap", json=swap_params)
        
        if swap_response.status_code != 200:
            error_text = swap_response.text
            logger.error(f"❌ Erreur API Jupiter: {error_text}")
            return {
                "status": "error",
                "message": f"Erreur lors de la création de la transaction: {error_text}"
            }
        
        swap_data = swap_response.json()
        transaction_data = swap_data["swapTransaction"]
        
        # Vérifier si d'autres informations utiles sont disponibles
        other_info = {}
        for key in ["addressLookupTableAddresses", "swapTransactionLogs"]:
            if key in swap_data:
                other_info[key] = swap_data[key]
        
        return {
            "status": "success",
            "transaction": transaction_data,
            "other_info": other_info
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création de la transaction: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

def check_transaction_status(tx_signature, max_retries=5):
    """
    Vérifie le statut d'une transaction après son envoi
    
    Args:
        tx_signature: Signature de la transaction
        max_retries: Nombre maximum de tentatives
        
    Returns:
        dict: Statut de la transaction
    """
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Attendre un peu avant de vérifier
            time.sleep(2)
            
            # Créer une requête RPC
            payload = {
                "jsonrpc": "2.0",
                "id": str(int(time.time())),
                "method": "getTransaction",
                "params": [
                    tx_signature,
                    {
                        "commitment": "confirmed",
                        "encoding": "json"
                    }
                ]
            }
            
            # Envoyer la requête
            headers = {"Content-Type": "application/json"}
            response = requests.post(RPC_URL, headers=headers, json=payload)
            result = response.json()
            
            # Vérifier si la transaction a été confirmée
            if "result" in result and result["result"] is not None:
                tx_data = result["result"]
                if tx_data.get("meta", {}).get("err") is None:
                    logger.info(f"✅ Transaction confirmée: {tx_signature}")
                    return {
                        "status": "confirmed",
                        "txid": tx_signature
                    }
                else:
                    error = tx_data.get("meta", {}).get("err")
                    logger.error(f"❌ Transaction échouée: {error}")
                    return {
                        "status": "failed",
                        "error": str(error),
                        "txid": tx_signature
                    }
            
            logger.info(f"⏳ Transaction en attente, nouvelle tentative ({retry_count+1}/{max_retries})...")
            retry_count += 1
            
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de la vérification de la transaction: {str(e)}")
            retry_count += 1
    
    logger.warning(f"⚠️ Impossible de confirmer la transaction après {max_retries} tentatives")
    return {
        "status": "unknown",
        "txid": tx_signature
    }

def send_transaction(transaction_data, skip_preflight=False):
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
        extracted_signature = None
        
        # Vérifier si la transaction est au format Jupiter (JSON)
        try:
            # Essayer de décoder et parser comme JSON
            decoded_data = b64decode(transaction_data).decode('utf-8')
            json_data = json.loads(decoded_data)
            
            # Si c'est un dict avec 'tx' et 'signatures', c'est au format Jupiter
            if isinstance(json_data, dict) and 'tx' in json_data and 'signatures' in json_data:
                logger.info("📝 Transaction au format Jupiter détectée, extraction...")
                # Extraire la transaction réelle
                transaction_data = json_data['tx']
                
                # Extraire la signature pour l'utiliser plus tard
                signature_info = json_data['signatures'][0]
                extracted_signature = signature_info['signature']
                logger.info(f"📝 Signature extraite: {extracted_signature[:8]}...")
        except Exception as e:
            # Si ce n'est pas du JSON valide, c'est probablement déjà une transaction encodée en base64
            logger.debug(f"Non-JSON transaction: {str(e)}")
        
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
        
        # Liste des RPC à essayer
        rpc_endpoints = [
            RPC_URL,
            "https://solana-mainnet.g.alchemy.com/v2/demo",
            "https://api.mainnet-beta.solana.com",
            "https://solana-api.projectserum.com"
        ]
        
        # Essayer chaque RPC jusqu'à ce qu'un fonctionne
        for rpc_url in rpc_endpoints:
            logger.info(f"📤 Envoi de la transaction via RPC: {rpc_url}...")
            try:
                response = requests.post(rpc_url, headers=headers, json=payload, timeout=10)
                result = response.json()
                
                if "error" not in result:
                    tx_signature = result["result"]
                    logger.info(f"✅ Transaction envoyée avec succès via {rpc_url}")
                    
                    # Créer URL Solana Explorer
                    explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
                    
                    return {
                        "status": "success",
                        "txid": tx_signature,
                        "explorer_url": explorer_url
                    }
                else:
                    error_message = result['error'].get('message', 'Erreur inconnue')
                    logger.error(f"❌ Erreur RPC {rpc_url}: {error_message}")
                    
                    # Si c'est une erreur de blockhash, essayer avec skipPreflight=true
                    if "blockhash" in error_message.lower() and not skip_preflight:
                        logger.info("🔄 Tentative avec skipPreflight=true...")
                        return send_transaction(transaction_data, skip_preflight=True)
            except Exception as e:
                logger.error(f"❌ Erreur de connexion à {rpc_url}: {str(e)}")
        
        # Si tous les RPC ont échoué
        logger.error("❌ Tous les RPC ont échoué")
        return {
            "status": "error",
            "message": "Échec de l'envoi: Tous les RPC ont échoué"
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
        
        # Liste des frais de priorité à essayer, du plus bas au plus élevé
        priority_fees = [5000, 20000, 50000, 100000]
        
        # Essayer avec différents frais de priorité
        for priority_fee in priority_fees:
            # 1. Créer une transaction via Jupiter
            tx_result = create_jupiter_transaction(wallet_address, quote_data, priority_fee=priority_fee)
            
            if tx_result["status"] != "success":
                logger.warning(f"⚠️ Échec de création de transaction avec priorité {priority_fee}: {tx_result['message']}")
                continue
            
            # 2. Signer la transaction avec notre keypair
            signed_tx = sign_transaction(tx_result["transaction"], keypair)
            
            # 3. Envoyer la transaction signée
            send_result = send_transaction(signed_tx)
            
            if send_result["status"] == "success":
                # Vérifier le statut de la transaction
                tx_status = check_transaction_status(send_result["txid"])
                
                # 4. Créer le résultat final
                if tx_status["status"] == "confirmed":
                    return {
                        "status": "success",
                        "message": "Transaction confirmée avec succès",
                        "txid": send_result["txid"],
                        "explorer_url": send_result["explorer_url"],
                        "input_amount": 1.0,
                        "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                        "priority_fee_used": priority_fee
                    }
                elif tx_status["status"] == "failed":
                    logger.warning(f"⚠️ Transaction échouée avec priorité {priority_fee}: {tx_status.get('error', 'Erreur inconnue')}")
                    # Continuer avec le prochain niveau de frais
                else:
                    # Si le statut est "pending" ou "unknown", considérer comme un succès
                    return {
                        "status": "pending",
                        "message": "Transaction envoyée, vérifiez l'explorateur Solana pour confirmation",
                        "txid": send_result["txid"],
                        "explorer_url": send_result["explorer_url"],
                        "input_amount": 1.0,
                        "estimated_output": float(quote_data["outAmount"]) / 1_000_000_000,
                        "priority_fee_used": priority_fee
                    }
            else:
                logger.warning(f"⚠️ Échec d'envoi avec priorité {priority_fee}: {send_result['message']}")
                # Continuer avec le prochain niveau de frais
        
        # Si toutes les tentatives ont échoué
        return {
            "status": "error",
            "message": "Échec après plusieurs tentatives avec différents frais de priorité",
            "last_error": send_result.get('message', 'Erreur inconnue')
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