import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from threat_analyzer import ThreatAnalyzer

# Load environment variables from .env if present
load_dotenv()

app = Flask(__name__)

# Initialize Threat Analyzer with environment keys if present
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")
SERPAPI_KEY = os.getenv("SERPAPI_API_KEY", "")

analyzer = ThreatAnalyzer(gemini_key=GEMINI_KEY, serpapi_key=SERPAPI_KEY)

PRESET_TESTS = [
    {
        "id": "bank_smishing",
        "label": "Urgent Bank OTP SMS",
        "category": "Smishing / Fraud",
        "description": "Urgent coercive SMS demanding KYC update via suspicious link",
        "content": "URGENT: Your SBI Bank account has been suspended due to pending KYC verification. Update immediately at http://sbi-kyc-verify.xyz/login or your account will be permanently blocked within 2 hours."
    },
    {
        "id": "brand_phishing",
        "label": "Brand Phishing URL",
        "category": "Phishing URL",
        "description": "PayPal typosquatting domain designed to steal login credentials",
        "content": "http://paypa1-security-verification.live/signin"
    },
    {
        "id": "crypto_scam",
        "label": "Crypto Giveaway Scam",
        "category": "Social Engineering",
        "description": "Unsolicited high-value cryptocurrency giveaway lure",
        "content": "Congratulations! You have been selected as a lucky winner of 1.5 BTC in the Binance 2026 Anniversary Giveaway! Click http://binance-claim-reward.top to claim your wallet transfer now."
    },
    {
        "id": "fake_job",
        "label": "Fake Job / WhatsApp Scam",
        "category": "Work Scam",
        "description": "Lucrative remote job offering demanding upfront registration fee",
        "content": "Hello! I am Sarah from Amazon HR. Earn $450/day working 1 hour from home reviewing products. No experience required. To activate your account, pay $25 processing fee to UPI id amazon-recruit@fakeupi."
    },
    {
        "id": "legit_bank_email",
        "label": "Legitimate Bank Notice",
        "category": "Verified Safe",
        "description": "Standard official communication directing user to verified portal",
        "content": "Dear Customer, your monthly e-statement for account ending in 4102 is now available. Log in securely to your NetBanking account at https://www.chase.com or through the official Chase Mobile App to view."
    },
    {
        "id": "safe_url",
        "label": "Safe Web URL",
        "category": "Verified Safe",
        "description": "Reputable, official developer platform URL",
        "content": "https://github.com/explore"
    }
]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/api/analyze", methods=["POST"])
def analyze_endpoint():
    data = request.get_json(force=True, silent=True) or {}
    input_text = data.get("input_text", "").strip()
    if not input_text:
        return jsonify({"status": "error", "message": "Please provide a URL or message to analyze."}), 400

    user_gemini_key = data.get("gemini_key", "").strip() or None
    user_serpapi_key = data.get("serpapi_key", "").strip() or None

    result = analyzer.analyze(input_text, user_gemini_key=user_gemini_key, user_serpapi_key=user_serpapi_key)
    return jsonify(result)

@app.route("/api/presets", methods=["GET"])
def get_presets():
    return jsonify(PRESET_TESTS)

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "gemini_active": bool(analyzer.gemini_key),
        "serpapi_active": bool(analyzer.serpapi_key),
        "fallback_ready": True
    })

@app.route("/api/save_keys", methods=["POST"])
def save_keys():
    data = request.get_json(force=True, silent=True) or {}
    gemini_key = data.get("gemini_key", "").strip()
    serpapi_key = data.get("serpapi_key", "").strip()
    
    analyzer.update_keys(gemini_key=gemini_key, serpapi_key=serpapi_key)
    return jsonify({
        "status": "success",
        "gemini_active": bool(analyzer.gemini_key),
        "serpapi_active": bool(analyzer.serpapi_key)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
