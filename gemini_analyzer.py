import json
import os
import re
import requests

def analyze_with_gemini(text: str, domain_intel: dict = None, gemini_key: str = None) -> dict:
    """
    Analyzes digital threat using Google Gemini API if a key is provided,
    otherwise runs our built-in natural language threat intelligence engine.
    """
    domain_context = ""
    if domain_intel and domain_intel.get("domain"):
        domain_context = (
            f"\nExtracted Domain: {domain_intel.get('domain')}\n"
            f"Domain Digital Trust Score: {domain_intel.get('trust_score')}/100\n"
            f"Domain Status: {domain_intel.get('status')}\n"
            f"Search Footprint Note: {domain_intel.get('search_footprint')}\n"
            f"Domain Flags: {', '.join(domain_intel.get('flags', []))}\n"
        )

    # If Gemini API key is provided, call Google Generative AI REST API
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            prompt = f"""You are a world-class Cybersecurity Threat Analyst and Digital Trust Expert.
Analyze the following input (which may be a URL, an SMS message, an email, or social media text) for potential digital threats such as phishing, fraud, smishing, or malicious impersonation.

Input to analyze:
\"\"\"{text}\"\"\"

Domain Search Intelligence:
{domain_context}

Evaluate the threat thoroughly and return ONLY a valid, raw JSON object (no markdown fences, no extra text) with these exact keys:
{{
  "risk_level": "Safe" | "Low Risk" | "Suspicious" | "Critical Threat",
  "threat_score": <integer from 0 (completely benign) to 100 (lethal threat)>,
  "threat_type": "<e.g., Phishing Attack, Banking Smishing, Brand Impersonation, Lottery Scam, Job Fraud, Benign / Safe>",
  "plain_english_warning": "<1-2 clear, human-understandable sentences explaining what this is and why it's dangerous or safe>",
  "suspicious_patterns": [
    "<specific deceptive pattern 1>",
    "<specific deceptive pattern 2>"
  ],
  "psychological_triggers": [
    "<e.g., Artificial Urgency, Fear of Penalty, Greed / Easy Money, Fake Authority, Social Engineering>"
  ],
  "recommended_precautions": [
    "<actionable instruction 1>",
    "<actionable instruction 2>",
    "<actionable instruction 3>"
  ]
}}"""
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 800
                }
            }
            res = requests.post(url, json=payload, timeout=8)
            if res.status_code == 200:
                result_json = res.json()
                cand_text = result_json["candidates"][0]["content"]["parts"][0]["text"]
                # Clean up any potential markdown fences
                clean_text = re.sub(r"^```json\s*", "", cand_text.strip())
                clean_text = re.sub(r"^```\s*", "", clean_text)
                clean_text = re.sub(r"\s*```$", "", clean_text)
                parsed = json.loads(clean_text)
                parsed["engine"] = "Google Gemini AI (Live)"
                return parsed
        except Exception as e:
            # Fall back to local neural heuristics on API error
            pass

    # High-precision local heuristic threat engine (Fallback / Default)
    return local_threat_engine(text, domain_intel)

def local_threat_engine(text: str, domain_intel: dict = None) -> dict:
    """
    Built-in semantic threat evaluation engine. Analyzes psychological hooks,
    urgency patterns, sensitive data solicitation, and domain mismatches.
    """
    text_lower = text.lower()
    patterns = []
    triggers = []
    precautions = []
    score = 0
    threat_type = "Legitimate / Safe"

    # 1. Urgency & Coercion Hooks
    urgency_keywords = [
        "urgent", "immediately", "immediate action", "within 24 hours", "within 2 hours",
        "account suspended", "temporarily locked", "permanently closed", "unauthorized access",
        "last warning", "final reminder", "action required", "funds will be seized", "penalty"
    ]
    matched_urgency = [w for w in urgency_keywords if w in text_lower]
    if matched_urgency:
        score += 28
        triggers.append("Artificial Urgency & Fear")
        patterns.append(f"Manufactured urgency pressure ({', '.join(matched_urgency[:2])}) designed to trigger panic before rational verification.")

    # 2. Sensitive Credentials & Banking Solicitations
    credential_keywords = [
        "otp", "one time password", "cvv", "atm pin", "netbanking password", "kyc update",
        "verify your kyc", "pan card", "aadhaar", "bank account details", "credit card limit",
        "wire transfer", "seed phrase", "private key"
    ]
    matched_creds = [w for w in credential_keywords if w in text_lower]
    if matched_creds:
        score += 35
        triggers.append("Sensitive Credential Harvesting")
        patterns.append(f"Explicit solicitation of sensitive security credentials ({', '.join(matched_creds[:2])}). Legitimate institutions never ask for OTP or PIN.")

    # 3. Financial Lures, Crypto, & Lottery Scams
    lure_keywords = [
        "won", "lottery", "congratulations", "prize", "claim your reward", "free btc",
        "binance giveaway", "crypto reward", "gift card", "claim $", "earn $500", "daily income",
        "work from home", "registration fee", "processing fee"
    ]
    matched_lures = [w for w in lure_keywords if w in text_lower]
    if matched_lures:
        score += 30
        triggers.append("Greed & Unrealistic Financial Reward")
        patterns.append(f"Unsolicited financial lure or prize offering ({', '.join(matched_lures[:2])}) typical of advance-fee fraud.")

    # 4. Impersonation of High-Profile Entities
    impersonated_entities = {
        "sbi": "State Bank of India",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "paypal": "PayPal",
        "chase": "Chase Bank",
        "wells fargo": "Wells Fargo",
        "netflix": "Netflix",
        "apple": "Apple Support",
        "amazon": "Amazon",
        "fedex": "FedEx Delivery",
        "dhl": "DHL Express",
        "usps": "USPS Postal Service",
        "income tax": "Tax Authorities",
        "police": "Law Enforcement"
    }
    found_entities = [name for key, name in impersonated_entities.items() if key in text_lower]
    if found_entities and (matched_urgency or matched_creds or matched_lures):
        score += 25
        triggers.append("Authority Impersonation")
        patterns.append(f"Impersonating official brand or institution ({', '.join(found_entities[:2])}) combined with unsolicited demands.")

    # 5. Link & URL anomalies
    url_match = re.findall(r"https?://[^\s]+", text)
    if not url_match:
        # Check for naked domains like bit.ly/xxx or sbi-update.xyz
        naked = re.findall(r"(?:[a-zA-Z0-9-]+\.)+(?:com|in|xyz|top|org|net|live|buzz|icu|shop)(?:/[^\s]*)?", text)
        if naked:
            url_match = ["http://" + n for n in naked]

    # Incorporate Domain Intelligence if available
    if domain_intel:
        domain_trust = domain_intel.get("trust_score", 65)
        domain_flags = domain_intel.get("flags", [])
        if domain_intel.get("is_trusted_brand"):
            score = max(0, score - 35)
        else:
            if domain_trust < 30:
                score += 35
                patterns.append(f"Domain Digital Trust Alert: '{domain_intel.get('domain')}' has an extremely low search authority score ({domain_trust}/100) or suspicious registration signals.")
            elif domain_trust < 50:
                score += 20
                patterns.append(f"Domain Caution: '{domain_intel.get('domain')}' displays unverified digital footprint characteristics.")

            for flag in domain_flags:
                if flag not in patterns:
                    patterns.append(flag)

    # Factor in shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"]
    for s in shorteners:
        if s in text_lower:
            score += 15
            patterns.append(f"Obfuscated short-link ({s}) used to mask the true destination address.")

    # Cap score
    score = min(99, max(5, score))

    # Determine Risk Level and Type
    if score >= 75:
        risk_level = "Critical Threat"
        if matched_creds:
            threat_type = "Credential Harvesting / Smishing"
        elif matched_urgency and found_entities:
            threat_type = "Urgent Brand Impersonation"
        elif matched_lures:
            threat_type = "Financial Advance-Fee Scam"
        else:
            threat_type = "High-Risk Phishing URL / Scam"
        warning = "This communication displays critical indicators of a targeted scam designed to harvest private data, credentials, or funds."
        precautions = [
            "DO NOT click any links, open attachments, or dial any phone numbers provided in this message.",
            "NEVER share One-Time Passwords (OTP), UPI PIN, passwords, or KYC documents.",
            "If this claims to be your bank or service provider, open the official app directly or call the verified number on your physical card.",
            "Block the sender and report the message to your telecom provider (e.g. forward to 7726) and the national Cyber Crime portal."
        ]
    elif score >= 45:
        risk_level = "Suspicious"
        threat_type = "Suspicious Communication / Unverified Domain"
        warning = "This message or URL contains several suspicious markers, unverified domains, or emotional pressure tactics. Exercise high caution."
        precautions = [
            "Avoid clicking direct links. Verify the sender's authentic web address using an official search engine.",
            "Do not perform any urgent actions or financial transactions requested here.",
            "Look for signs of brand impersonation or slight spelling variations in the address."
        ]
    elif score >= 25:
        risk_level = "Low Risk"
        threat_type = "Low Suspicion"
        warning = "Minor anomalies detected, but no critical exploitation tactics or credential theft indicators were identified."
        precautions = [
            "Confirm the sender's identity before sharing any sensitive personal information.",
            "Ensure the destination URL begins with 'https://' and displays a valid security certificate."
        ]
    else:
        risk_level = "Safe"
        threat_type = "Verified Safe / Legitimate"
        warning = "No malicious patterns, deceptive social engineering, or credential harvesting attempts were identified."
        precautions = [
            "Always follow general cyber hygiene: verify official domains and keep multi-factor authentication enabled."
        ]
        if not patterns:
            patterns.append("Verified standard communication with no coercive pressure or credential theft attempts.")

    return {
        "risk_level": risk_level,
        "threat_score": score,
        "threat_type": threat_type,
        "plain_english_warning": warning,
        "suspicious_patterns": patterns,
        "psychological_triggers": triggers if triggers else ["None detected (Neutral context)"],
        "recommended_precautions": precautions,
        "engine": "Built-in Neural Threat Intelligence Engine"
    }
