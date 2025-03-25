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
        
        # Obtenir un blockhash récent via RPC direct - essayer plusieurs endpoints
        rpc_endpoints = [
            RPC_URL,
            "https://api.mainnet-beta.solana.com",
            "https://solana-mainnet.rpc.extrnode.com",
            "https://rpc.ankr.com/solana"
        ]
        
        recent_blockhash = None
        for rpc_url in rpc_endpoints:
            try:
                rpc_response = requests.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getLatestBlockhash",
                        "params": [{"commitment": "finalized"}]
                    },
                    timeout=5
                )
                if rpc_response.status_code == 200:
                    result = rpc_response.json()
                    if "result" in result and "value" in result["result"]:
                        recent_blockhash = result["result"]["value"]["blockhash"]
                        logger.info(f"✅ Blockhash récent obtenu: {recent_blockhash}")
                        break
            except Exception as e:
                logger.debug(f"Échec d'obtention du blockhash via {rpc_url}: {str(e)}")
        
        if not recent_blockhash:
            logger.warning("⚠️ Impossible d'obtenir un blockhash récent, utilisation de la transaction telle quelle")
        
        # Détection du format de transaction
        is_versioned = False
        try:
            # Vérifier si c'est une transaction versionnée (commence par 0x80)
            if transaction_bytes and len(transaction_bytes) > 0 and transaction_bytes[0] == 0x80:
                is_versioned = True
                logger.info("🔍 Transaction versionnée détectée (format 0x80)")
        except Exception:
            pass
        
        # Essayer d'abord de traiter comme une transaction versionnée (format Jupiter v6)
        if is_versioned:
            try:
                from solders.transaction import VersionedTransaction
                from solders.signature import Signature as SoldersSignature
                
                # Désérialiser comme une transaction versionnée
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
                logger.warning(f"⚠️ Erreur lors de la signature de transaction versionnée: {str(e_versioned)}")
        
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
            "slippageBps": 100,  # 1% de slippage maximum
            "platformFeeBps": 0  # Pas de frais de plateforme
            # Ne pas inclure onlyDirectRoutes pour éviter les erreurs de parsing
        }
        
        logger.info(f"🔍 Obtention du devis pour {amount_usdc} USDC → SOL...")
        
        # Essayer plusieurs fois avec backoff exponentiel
        max_retries = 3
        for retry in range(max_retries):
            try:
                if retry > 0:
                    backoff_time = 1 * (2 ** retry)  # 2s, 4s, 8s
                    logger.info(f"⏱️ Tentative {retry+1}/{max_retries} pour obtenir un devis (attente: {backoff_time}s)...")
                    time.sleep(backoff_time)
                
                # Log the exact URL and parameters being sent
                request_url = f"{JUPITER_API_BASE}/quote"
                logger.info(f"🔍 Requête API: {request_url} avec paramètres: {quote_params}")
                
                # Utiliser une session requests pour plus de contrôle
                session = requests.Session()
                
                # Construire l'URL manuellement pour éviter tout problème de sérialisation
                url_params = []
                for key, value in quote_params.items():
                    # Convertir les valeurs en chaînes appropriées
                    if isinstance(value, bool):
                        # Convertir les booléens en 'true' ou 'false' (minuscules)
                        url_params.append(f"{key}={'true' if value else 'false'}")
                    else:
                        url_params.append(f"{key}={value}")
                
                full_url = f"{request_url}?{'&'.join(url_params)}"
                logger.info(f"🔍 URL construite manuellement: {full_url}")
                
                response = session.get(full_url, timeout=15)
                
                # Log the actual request URL that was sent
                logger.info(f"🔍 URL complète envoyée: {response.request.url}")
                
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
                elif response.status_code == 429:
                    # Rate limit - attendre plus longtemps
                    logger.warning(f"⚠️ Rate limit atteint sur l'API Jupiter (429), attente avant nouvelle tentative...")
                    time.sleep(5)  # Attente plus longue pour rate limit
                else:
                    logger.warning(f"⚠️ Erreur API Jupiter: {response.status_code} - {response.text}")
                    
                    # Si c'est une erreur de validation ou de paramètres, ne pas réessayer
                    if response.status_code in [400, 422]:
                        return {
                            "status": "error",
                            "message": f"Erreur API Jupiter: {response.status_code} - {response.text}"
                        }
            except requests.exceptions.Timeout:
                logger.warning(f"⚠️ Timeout lors de l'obtention du devis (tentative {retry+1}/{max_retries})")
            except requests.exceptions.ConnectionError:
                logger.warning(f"⚠️ Erreur de connexion à l'API Jupiter (tentative {retry+1}/{max_retries})")
            except Exception as e:
                logger.warning(f"⚠️ Erreur lors de l'obtention du devis: {str(e)} (tentative {retry+1}/{max_retries})")
        
        # Toutes les tentatives ont échoué
        logger.error("❌ Échec d'obtention du devis après plusieurs tentatives")
        return {
            "status": "error",
            "message": "Échec d'obtention du devis après plusieurs tentatives"
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
            "prioritizationFeeLamports": priority_fee,
            "maxRetries": 3
        }
        
        logger.info(f"🏗️ Création d'une transaction via Jupiter (priorité: {priority_fee} lamports)...")
        
        # Essayer plusieurs fois avec backoff exponentiel
        max_retries = 3
        for retry in range(max_retries):
            try:
                if retry > 0:
                    backoff_time = 1 * (2 ** retry)  # 2s, 4s, 8s
                    logger.info(f"⏱️ Tentative {retry+1}/{max_retries} pour créer la transaction (attente: {backoff_time}s)...")
                    time.sleep(backoff_time)
                
                swap_response = requests.post(
                    f"{JUPITER_API_BASE}/swap", 
                    json=swap_params,
                    timeout=15  # Timeout augmenté
                )
                
                if swap_response.status_code == 200:
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
                elif swap_response.status_code == 429:
                    # Rate limit - attendre plus longtemps
                    logger.warning(f"⚠️ Rate limit atteint sur l'API Jupiter (429), attente avant nouvelle tentative...")
                    time.sleep(5)  # Attente plus longue pour rate limit
                else:
                    error_text = swap_response.text
                    logger.warning(f"⚠️ Erreur API Jupiter: {swap_response.status_code} - {error_text}")
                    
                    # Si c'est une erreur de validation ou de paramètres, ne pas réessayer
                    if swap_response.status_code in [400, 422]:
                        logger.error(f"❌ Erreur de validation Jupiter: {error_text}")
                        return {
                            "status": "error",
                            "message": f"Erreur lors de la création de la transaction: {error_text}"
                        }
            except requests.exceptions.Timeout:
                logger.warning(f"⚠️ Timeout lors de la création de transaction (tentative {retry+1}/{max_retries})")
            except requests.exceptions.ConnectionError:
                logger.warning(f"⚠️ Erreur de connexion à l'API Jupiter (tentative {retry+1}/{max_retries})")
            except Exception as e:
                logger.warning(f"⚠️ Erreur lors de la création de transaction: {str(e)} (tentative {retry+1}/{max_retries})")
        
        # Toutes les tentatives ont échoué
        logger.error("❌ Échec de création de transaction après plusieurs tentatives")
        return {
            "status": "error",
            "message": "Échec de création de transaction après plusieurs tentatives"
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
    # Liste des RPC à essayer
    rpc_endpoints = [
        RPC_URL,
        "https://api.mainnet-beta.solana.com",
        "https://solana-mainnet.rpc.extrnode.com",
        "https://rpc.ankr.com/solana"
    ]
    
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Attendre un peu avant de vérifier (temps d'attente croissant)
            wait_time = 2 * (1 + retry_count * 0.5)  # 2s, 3s, 4s, 5s, 6s
            logger.info(f"⏳ Vérification du statut dans {wait_time:.1f}s (tentative {retry_count+1}/{max_retries})...")
            time.sleep(wait_time)
            
            # Essayer chaque RPC jusqu'à ce qu'un fonctionne
            for rpc_url in rpc_endpoints:
                try:
                    # Créer une requête RPC
                    payload = {
                        "jsonrpc": "2.0",
                        "id": str(int(time.time())),
                        "method": "getTransaction",
                        "params": [
                            tx_signature,
                            {
                                "commitment": "confirmed",
                                "encoding": "json",
                                "maxSupportedTransactionVersion": 0
                            }
                        ]
                    }
                    
                    # Envoyer la requête
                    headers = {"Content-Type": "application/json"}
                    response = requests.post(rpc_url, headers=headers, json=payload, timeout=10)
                    
                    if response.status_code != 200:
                        logger.warning(f"⚠️ Statut HTTP non-200 de {rpc_url}: {response.status_code}")
                        continue
                    
                    result = response.json()
                    
                    # Vérifier si la transaction a été confirmée
                    if "result" in result and result["result"] is not None:
                        tx_data = result["result"]
                        if tx_data.get("meta", {}).get("err") is None:
                            logger.info(f"✅ Transaction confirmée: {tx_signature}")
                            return {
                                "status": "confirmed",
                                "txid": tx_signature,
                                "rpc_used": rpc_url
                            }
                        else:
                            error = tx_data.get("meta", {}).get("err")
                            logger.error(f"❌ Transaction échouée: {error}")
                            return {
                                "status": "failed",
                                "error": str(error),
                                "txid": tx_signature,
                                "rpc_used": rpc_url
                            }
                    elif "error" in result:
                        error_msg = result["error"].get("message", "Erreur inconnue")
                        logger.warning(f"⚠️ Erreur RPC {rpc_url}: {error_msg}")
                        # Si c'est une erreur de transaction non trouvée, essayer un autre RPC
                        continue
                    else:
                        # Transaction pas encore confirmée, essayer un autre RPC
                        logger.info(f"⏳ Transaction non trouvée sur {rpc_url}, essai d'un autre RPC...")
                        continue
                        
                except requests.exceptions.Timeout:
                    logger.warning(f"⚠️ Timeout lors de la vérification via {rpc_url}")
                except requests.exceptions.ConnectionError:
                    logger.warning(f"⚠️ Erreur de connexion à {rpc_url}")
                except Exception as e:
                    logger.warning(f"⚠️ Erreur lors de la vérification via {rpc_url}: {str(e)}")
            
            # Si on arrive ici, aucun RPC n'a trouvé la transaction
            logger.info(f"⏳ Transaction en attente, nouvelle tentative ({retry_count+1}/{max_retries})...")
            retry_count += 1
            
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de la vérification de la transaction: {str(e)}")
            retry_count += 1
    
    logger.warning(f"⚠️ Impossible de confirmer la transaction après {max_retries} tentatives")
    return {
        "status": "unknown",
        "txid": tx_signature,
        "message": f"Statut inconnu après {max_retries} tentatives de vérification"
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
        
        # Liste des RPC à essayer - ajout de plusieurs endpoints fiables
        rpc_endpoints = [
            RPC_URL,
            "https://api.mainnet-beta.solana.com",
            "https://solana-mainnet.rpc.extrnode.com",
            "https://solana.api.chainstack.com/mainnet-beta",
            "https://mainnet.helius-rpc.com/?api-key=1d8740dc-e5f4-421c-b823-e1bad1889eff",
            "https://solana-mainnet.g.alchemy.com/v2/demo",
            "https://solana-api.projectserum.com",
            "https://rpc.ankr.com/solana"
        ]
        
        # Fonction pour essayer un RPC avec backoff exponentiel
        def try_rpc_with_backoff(rpc_url, max_retries=3):
            for retry in range(max_retries):
                try:
                    backoff_time = 0.5 * (2 ** retry)  # 0.5s, 1s, 2s
                    if retry > 0:
                        logger.info(f"⏱️ Tentative {retry+1}/{max_retries} pour {rpc_url} (attente: {backoff_time}s)...")
                        time.sleep(backoff_time)
                    
                    response = requests.post(rpc_url, headers=headers, json=payload, timeout=15)  # Timeout augmenté
                    
                    # Vérifier si la réponse est valide
                    if response.status_code != 200:
                        logger.warning(f"⚠️ Statut HTTP non-200 de {rpc_url}: {response.status_code}")
                        continue
                    
                    try:
                        result = response.json()
                    except ValueError:
                        logger.warning(f"⚠️ Réponse non-JSON de {rpc_url}")
                        continue
                    
                    if "error" not in result:
                        tx_signature = result["result"]
                        logger.info(f"✅ Transaction envoyée avec succès via {rpc_url}")
                        
                        # Créer URL Solana Explorer
                        explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=mainnet-beta"
                        
                        return {
                            "status": "success",
                            "txid": tx_signature,
                            "explorer_url": explorer_url,
                            "rpc_used": rpc_url
                        }
                    else:
                        error_message = result['error'].get('message', 'Erreur inconnue')
                        error_code = result['error'].get('code', 0)
                        logger.warning(f"⚠️ Erreur RPC {rpc_url}: {error_message} (code: {error_code})")
                        
                        # Si c'est une erreur de signature, c'est probablement un problème avec la transaction
                        if "signature verification failure" in error_message.lower():
                            logger.error(f"❌ Erreur de vérification de signature sur {rpc_url}")
                            # Ne pas réessayer ce RPC, mais continuer avec les autres
                            return {
                                "status": "error",
                                "message": f"Erreur de vérification de signature: {error_message}",
                                "rpc_used": rpc_url,
                                "retry_different_rpc": True
                            }
                        
                        # Si c'est une erreur de blockhash, essayer avec skipPreflight=true
                        if ("blockhash" in error_message.lower() or 
                            "block height" in error_message.lower() or 
                            "too old" in error_message.lower()) and not skip_preflight:
                            logger.info("🔄 Tentative avec skipPreflight=true...")
                            return send_transaction(transaction_data, skip_preflight=True)
                except requests.exceptions.Timeout:
                    logger.warning(f"⚠️ Timeout pour {rpc_url} (tentative {retry+1}/{max_retries})")
                except requests.exceptions.ConnectionError:
                    logger.warning(f"⚠️ Erreur de connexion à {rpc_url} (tentative {retry+1}/{max_retries})")
                except Exception as e:
                    logger.warning(f"⚠️ Erreur avec {rpc_url}: {str(e)} (tentative {retry+1}/{max_retries})")
            
            # Toutes les tentatives ont échoué pour ce RPC
            return {
                "status": "error",
                "message": f"Échec après {max_retries} tentatives sur {rpc_url}",
                "rpc_used": rpc_url,
                "retry_different_rpc": True
            }
        
        # Essayer chaque RPC jusqu'à ce qu'un fonctionne
        last_error = None
        for rpc_url in rpc_endpoints:
            logger.info(f"📤 Envoi de la transaction via RPC: {rpc_url}...")
            result = try_rpc_with_backoff(rpc_url)
            
            if result["status"] == "success":
                return result
            
            last_error = result
            
            # Si ce n'est pas une erreur qui suggère d'essayer un autre RPC, arrêter ici
            if not result.get("retry_different_rpc", False):
                break
        
        # Si tous les RPC ont échoué
        logger.error("❌ Tous les RPC ont échoué")
        error_message = last_error.get("message", "Raison inconnue") if last_error else "Tous les RPC ont échoué"
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
        priority_fees = [5000, 20000, 50000, 100000, 200000]
        
        # Stocker les erreurs pour chaque tentative
        attempt_errors = []
        
        # Essayer avec différents frais de priorité
        for priority_fee in priority_fees:
            # 1. Créer une transaction via Jupiter
            tx_result = create_jupiter_transaction(wallet_address, quote_data, priority_fee=priority_fee)
            
            if tx_result["status"] != "success":
                error_msg = f"Échec de création de transaction avec priorité {priority_fee}: {tx_result.get('message', 'Erreur inconnue')}"
                logger.warning(f"⚠️ {error_msg}")
                attempt_errors.append({
                    "priority_fee": priority_fee,
                    "stage": "creation",
                    "error": tx_result.get('message', 'Erreur inconnue')
                })
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
                        "priority_fee_used": priority_fee,
                        "rpc_used": send_result.get("rpc_used", "unknown")
                    }
                elif tx_status["status"] == "failed":
                    error_msg = f"Transaction échouée avec priorité {priority_fee}: {tx_status.get('error', 'Erreur inconnue')}"
                    logger.warning(f"⚠️ {error_msg}")
                    attempt_errors.append({
                        "priority_fee": priority_fee,
                        "stage": "confirmation",
                        "error": tx_status.get('error', 'Erreur inconnue'),
                        "txid": send_result["txid"]
                    })
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
                        "priority_fee_used": priority_fee,
                        "rpc_used": send_result.get("rpc_used", "unknown")
                    }
            else:
                error_msg = f"Échec d'envoi avec priorité {priority_fee}: {send_result.get('message', 'Erreur inconnue')}"
                logger.warning(f"⚠️ {error_msg}")
                attempt_errors.append({
                    "priority_fee": priority_fee,
                    "stage": "sending",
                    "error": send_result.get('message', 'Erreur inconnue'),
                    "rpc_used": send_result.get("rpc_used", "unknown")
                })
                # Continuer avec le prochain niveau de frais
        
        # Si toutes les tentatives ont échoué
        last_error = "Erreur inconnue"
        if attempt_errors:
            last_error = attempt_errors[-1].get('error', 'Erreur inconnue')
        
        return {
            "status": "error",
            "message": "Échec après plusieurs tentatives avec différents frais de priorité",
            "last_error": last_error,
            "attempt_errors": attempt_errors,
            "attempted_priority_fees": priority_fees
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