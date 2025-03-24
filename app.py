from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route("/status")
def status():
    return jsonify({
        "bot": "Kairos",
        "wallet": os.getenv("WALLET_ADDRESS"),
        "network": "mainnet-beta",
        "status": "active"
    })

@app.route("/pnl")
def pnl():
    return jsonify({
        "total_gain_percent": 0.0,
        "trades_executed": 0
    })

@app.route("/last-trade")
def last_trade():
    return jsonify({
        "token_in": "USDC",
        "token_out": "SOL",
        "amount_in": 1.0,
        "amount_out": 0.021,
        "tx_signature": "TBD"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
