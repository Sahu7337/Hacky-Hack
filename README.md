# Sifter — AI-Powered Digital Threat Detection & Digital Trust Engine

> **Hackathon 2026 — Track 1: Cybersecurity & Digital Trust**  
> *AI-Powered Digital Threat Detection Platform*

---

## 📌 Project Overview

**Sifter** is an AI-powered digital trust and threat detection engine designed to protect citizens from phishing URLs, fraudulent messages, banking scams, and social engineering attacks. 

Unlike traditional security systems that rely on slow, reactive blacklists or overwhelm users with cryptic technical jargon, **Sifter** introduces a clean, minimalist search-engine-inspired interface (black, white, and light grey palette) that provides:
1. **Search Footprint Intelligence (SerpAPI / Google Search Indexing)**: Evaluates whether a domain actually possesses an established, authentic search presence on Google. If the search authority is low or zero, or if typosquatting is detected, the trust score drops immediately.
2. **Contextual AI Threat Reasoning (Google Gemini AI)**: Evaluates semantic manipulation, psychological coercion (urgency, panic, fear), credential harvesting attempts (OTP/PIN/CVV), and brand impersonation.
3. **Understandable Risk Assessment & Safety Precautions**: Converts complex threat indicators into plain-English explanations and step-by-step precautions that anyone can understand and act upon.
4. **Future Scope Roadmap**: An autonomous cross-platform agent for phones and laptops that proactively intercepts and blocks outbound malicious messages before the user sends them.

---

## 🏆 Fulfillment of Minimum Hackathon Requirements

| Minimum Requirement | Implementation in Sifter |
| :--- | :--- |
| **1. Accept a URL or message for analysis** | Central minimalist search omnibar accepts single URLs, multi-line SMS, emails, or chat messages. Automatically detects URLs, parses entities, and extracts domain origins. |
| **2. Identify suspicious patterns & generate threat assessment** | Multi-layered detection pipeline: Domain typosquatting, high-risk TLDs, Google Search index presence (SerpAPI), psychological urgency triggers, and sensitive credential harvesting. |
| **3. Display risk level with reasons & recommended precautions** | Features a 0–100 Digital Trust Score with color-coded risk tiers (`VERIFIED SAFE`, `SUSPICIOUS / CAUTION`, `FAKE / UNSAFE THREAT`), plain-English warnings, identified manipulation tactics, and numbered actionable precautions. |
| **4. Provide a functional interface for users to test the system** | Fully functional, responsive web application with 6 one-click preloaded test scenarios (Bank Smishing, PayPal Phishing, Crypto Giveaway, Fake Job Scam, Legitimate Bank Email, Safe URL) and real-time scanning. |

---

## 🧠 System Architecture

```
[ User Input: URL, SMS, or Email ]
                │
                ├──► 1. Entity & Domain Extraction (RegEx & URL parsing)
                │
                ├──► 2. SerpAPI Search Intelligence (Trust-Score Verification)
                │       • Checks Google Search index footprint
                │       • Detects zero-indexed domains & fresh disposable hosts
                │       • Identifies brand typosquatting (e.g., paypa1 vs paypal.com)
                │       • Flags domains indexed in fraud/scam advisories
                │
                ├──► 3. Google Gemini AI Analysis (Contextual Threat Reasoning)
                │       • Detects artificial urgency, fear, greed, & authority impersonation
                │       • Identifies OTP, CVV, and KYC harvesting demands
                │       • Evaluates correlation between message claims & search footprint
                │
                └──► 4. Output: Unified Trust Report
                        • Trust Score (0–100) & Risk Level Badge
                        • Plain-English Warning & Reasons
                        • SerpAPI Search Footprint Evidence
                        • Tailored Safety Precautions
```

---

## 🛠️ Technology Stack

- **Frontend**: Clean HTML5, CSS3, Modern Vanilla JavaScript (Ultra-responsive, pure Black, White, Light Grey minimalist design, dark/light theme toggle).
- **Backend**: Python 3 (Flask, Requests, NumPy, Scikit-learn, Python-dotenv).
- **External AI & Search APIs**:
  - **Google Gemini API**: Semantic reasoning, behavioral pattern recognition, and plain-English recommendations.
  - **SerpAPI / Google Search Engine**: Domain index presence, brand authority matching, and search trust scoring.
  - **Built-in Neural Fallback Engine**: If API keys are not supplied, Sifter automatically runs using its high-precision built-in neural NLP and search footprint knowledge base so that judges can test the platform 100% out of the box with zero setup friction!

---

## 🚀 How to Run the Application

### 1. Activate the Virtual Environment
```bash
cd /home/asishranjan/digital-threat-detection
source venv/bin/activate
```

### 2. (Optional) Configure API Keys
You can set your keys via environment variables, `.env` file, or directly within the web UI's **"APIs"** modal:
```bash
cp .env.example .env
# Edit .env with your keys:
# GEMINI_API_KEY=your_key_here
# SERPAPI_API_KEY=your_key_here
```
*Note: If keys are omitted, the application will seamlessly use its high-precision built-in neural engine.*

### 3. Launch the Server
```bash
python3 app.py
```
Open your web browser and navigate to:
```
http://localhost:5000
```

---

## 📱 Future Scope: Phone & Laptop Native App

A key differentiator highlighted in the Sifter architecture is the roadmap for cross-platform endpoint security:

1. **Pre-Send Outbound Message Blocker**:
   - Background daemon on mobile (Android/iOS) and desktop (Windows/macOS/Linux).
   - When a user drafts a message in messaging apps (WhatsApp, Telegram, SMS, Slack) and is about to tap send, Sifter analyzes outbound links in real-time. If the link is flagged as phishing or scam, transmission is immediately blocked to protect the user's contacts.
2. **Real-Time Clipboard Shield**:
   - Inspects copied links in memory, catching homoglyphs and disguised URLs before they are pasted into browsers.
3. **Zero-Knowledge Local Verification**:
   - Privacy-preserving architecture that analyzes behavioral patterns locally on device without storing private chat history.

---

## 🧪 Preloaded Test Scenarios

The web interface includes 6 one-click interactive scenarios for testing:
1. **Urgent Bank OTP SMS (Smishing)**: *"URGENT: Your SBI Bank account has been suspended... Update KYC immediately at http://sbi-kyc-verify.xyz/login"* -> Flagged as **Critical Threat**.
2. **Brand Phishing URL**: `http://paypa1-security-verification.live/signin` -> Flagged as **Critical Threat (Typosquatting)**.
3. **Crypto Giveaway Scam**: 1.5 BTC Binance giveaway scam link -> Flagged as **Critical Threat (Financial Lure)**.
4. **Fake Job / WhatsApp Scam**: Amazon HR $450/day remote review job asking for registration fee -> Flagged as **Critical Threat (Work Scam)**.
5. **Legitimate Bank Notice**: Genuine Chase Bank statement notification with verified `https://chase.com` link -> Flagged as **Verified Safe (94/100)**.
6. **Safe Web URL**: `https://github.com/explore` -> Flagged as **Verified Safe (98/100)**.
