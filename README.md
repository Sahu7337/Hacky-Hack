# Sifter — AI-Powered Digital Threat Detection and Digital Trust Engine

> ⚡ **Hackathon 2026 — Track: Cybersecurity & Digital Trust**  
> **Recognition:** Top 6 Finalist  
> **Build:** Conceived, architected, and built solo in an intense 3-hour sprint.  
> **Tagline:** Know before you click.

---

## 1. Project Overview

Sifter is an AI-powered digital trust and threat detection platform engineered to protect users from malicious URLs, phishing messages, smishing fraud, financial lures, and social engineering attacks.

Traditional security systems rely on static, slow-updating blacklists or burden users with opaque technical jargon. Sifter introduces a streamlined search-engine-inspired interface designed around clarity, trust, and speed:

1. Search Footprint Intelligence (SerpAPI / Google Search Indexing): Audits whether a domain holds an established, legitimate presence on the Google Search index. Disposable domains, zero-indexed hosts, or brand impersonators are flagged instantly.
2. Contextual AI Threat Reasoning (Google Gemini AI): Analyzes natural language semantics, psychological coercion (urgency, fear, greed, fake authority), credential harvesting demands (OTP, PIN, passwords), and deceptive framing.
3. Plain-English Threat Explanations: Translates complex security telemetry into actionable, jargon-free verdicts and numbered safety steps that anyone can follow.
4. Seamless Fallback Resilience: If API keys are not provided, built-in heuristic pattern recognition and known threat signatures run automatically, ensuring zero setup friction.

---

## 2. Fulfillment of Hackathon Minimum Requirements

| Minimum Requirement | Implementation in Sifter |
| :--- | :--- |
| 1. Accept a URL or message for analysis | Centered omnibar accepts single URLs, multi-line SMS, phishing emails, or chat messages. Automatically extracts entities, domain origins, and intent. |
| 2. Identify suspicious patterns and generate threat assessment | Multi-layered detection pipeline: Brand typosquatting, high-risk TLDs, Google Search index presence, psychological pressure cues, and sensitive credential harvesting. |
| 3. Display risk level with reasons and recommended precautions | Features a 0–100 Digital Trust Score, categorized risk badges (Verified Safe, Suspicious / Caution, Fake / Unsafe Threat), plain-English warnings, identified manipulation tactics, and actionable precautions. |
| 4. Provide a functional interface for users to test the system | Responsive, cardless web application with 6 preloaded interactive test scenarios covering smishing, brand typosquatting, crypto scams, job fraud, verified banking portals, and safe developer platforms. |

---

## 3. System Architecture and Detection Pipeline

```
[ User Input: Suspicious URL, SMS, or Email Message ]
                         |
                         v
     [ 1. Entity and Domain Parsing Pipeline ]
     - URL extraction and protocol verification
     - Domain isolation and homoglyph normalization
     - Top-Level Domain (TLD) risk classification
                         |
         +---------------+---------------+
         |                               |
         v                               v
[ 2. SerpAPI Search Intelligence ]  [ 3. Google Gemini 2.5 Flash ]
- Query live Google Search index    - Contextual threat reasoning
- Evaluate index presence & age     - Psychological trigger extraction
- Detect zero-indexed domains       - Impersonation and urgency audit
- Flag known scam advisories        - Plain-English warning generation
         |                               |
         +---------------+---------------+
                         |
                         v
       [ 4. Unified Digital Trust Engine ]
       - Calculate Digital Trust Score (0 to 100)
       - Classify Threat Tier (Safe / Caution / Critical)
       - Compile domain evidence and manipulation flags
       - Generate actionable, step-by-step precautions
                         |
                         v
   [ 5. Responsive Minimalist Frontend Presentation ]
   - Center-aligned search omnibar with fluid morphing
   - Cardless, unboxed editorial result flow
   - Direct AI disclaimer: Sifter uses AI and can make mistakes.
```

---

## 4. Key Capabilities

### A. Dual-Engine Intelligence
- Google Gemini 2.5 Flash: Evaluates linguistic context, conversational manipulation, pressure tactics, and fraudulent value propositions.
- SerpAPI Google Search Footprint: Verifies if a domain has an authentic digital footprint. Brand new, un-indexed domains masquerading as established financial or tech services are penalized heavily.
- Built-In Neural Fallback Engine: Provides deterministic heuristics for offline or unauthenticated testing, guaranteeing system availability.

### B. Dynamic Trust Scoring (0 to 100)
- 80 to 100 (Verified Safe): Established digital footprint, verified certificates, legitimate corporate communication.
- 50 to 79 (Suspicious / Caution): Unverified domain, newly registered infrastructure, or ambiguous sender intent.
- 0 to 49 (Fake / Unsafe Threat): Explicit credential harvesting, brand typosquatting, high-risk TLD, or aggressive urgency triggers.

### C. Psychological Manipulation Analysis
Identifies and categorizes social engineering vectors used by threat actors:
- Artificial Urgency: "Within 2 hours", "Immediate action required"
- Fear of Penalty: "Account suspended", "Permanent block", "Legal summons"
- Greed and Financial Lures: "1.5 BTC giveaway", "Earn $450/day reviewing products"
- Fake Authority: Impersonation of major institutions (Banks, PayPal, Amazon, Binance)

---

## 5. Design Philosophy and Interface

Sifter follows an unboxed, text-only editorial design system inspired by minimalist typography and modern AI chat interfaces:

- Monochromatic Palette: Pure Black (#09090b), Slate Grey (#18181b), and Crisp White (#f4f4f5).
- Centered Search Omnibar: Positioned at the optical center of the viewport with tagline "Know before you click."
- Fluid Morphing Physics:
  - Starts as a compact pill shape (`border-radius: 28px`).
  - Smoothly morphs into a rounded rectangle (`border-radius: 18px`) when multi-line text or newlines are entered, utilizing synchronized Apple-style easing (`cubic-bezier(0.16, 1, 0.3, 1)`).
  - Eliminates transition jank via an off-screen measurement clone (`ghostMeasurer`), preventing `style.height = 'auto'` layout flickering.
- Cardless Structure: Completely eliminates heavy container boxes and divider lines across the samples drawer, result breakdown, and the `/about` page.
- Direct AI Disclaimer: Snugly positioned directly below the search bar:
  "Sifter uses AI and can make mistakes. Double-check before sharing sensitive info."

---

## 6. Preloaded Test Scenarios

The web interface features 6 interactive one-click presets via the Samples drawer:

1. Urgent Bank OTP SMS (Smishing)
   - Input: "URGENT: Your SBI Bank account has been suspended due to pending KYC verification. Update immediately at http://sbi-kyc-verify.xyz/login..."
   - Verdict: Critical Threat (Trust Score: 8/100)
   - Flags: High-abuse TLD (.xyz), KYC credential harvesting, artificial urgency.

2. Brand Phishing URL (Typosquatting)
   - Input: "http://paypa1-security-verification.live/signin"
   - Verdict: Critical Threat (Trust Score: 5/100)
   - Flags: Visual homoglyph ("paypa1"), high-risk TLD (.live), unindexed domain footprint.

3. Crypto Giveaway Scam (Financial Lure)
   - Input: "Congratulations! You have been selected as a lucky winner of 1.5 BTC in the Binance 2026 Anniversary Giveaway! Click http://binance-claim-reward.top..."
   - Verdict: Critical Threat (Trust Score: 10/100)
   - Flags: Unsolicited cryptocurrency transfer claim, disposable domain (.top).

4. Fake Job / WhatsApp Scam (Work Scam)
   - Input: "Hello! I am Sarah from Amazon HR. Earn $450/day working 1 hour from home... pay $25 processing fee..."
   - Verdict: Critical Threat (Trust Score: 12/100)
   - Flags: Advance-fee employment scam, brand impersonation.

5. Legitimate Bank Notice (Verified Safe)
   - Input: "Dear Customer, your monthly e-statement for account ending in 4102 is now available. Log in securely to your NetBanking account at https://www.chase.com..."
   - Verdict: Verified Safe (Trust Score: 94/100)
   - Flags: Legitimate domain with high search footprint authority.

6. Safe Developer Platform (Verified Safe)
   - Input: "https://github.com/explore"
   - Verdict: Verified Safe (Trust Score: 98/100)
   - Flags: Highly indexed official repository domain.

---

## 7. Technology Stack

- Backend: Python 3, Flask, Requests, NumPy, Scikit-learn, Python-dotenv
- Frontend: HTML5, CSS3, Vanilla JavaScript (Zero bloated frameworks, pure CSS transitions)
- AI Engine: Google Gemini API (`gemini-2.5-flash`)
- Search Intelligence: SerpAPI (Google Search Engine Footprint API)
- Fonts: Plus Jakarta Sans, Poppins, Comfortaa, Nunito

---

## 8. Installation and Local Setup

### Prerequisites
- Python 3.10 or higher
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/Sahu7337/Hacky-Hack.git
cd Hacky-Hack
```

### Step 2: Set Up Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure API Keys (Optional)
Sifter runs out of the box with built-in heuristic threat detection even without API keys. To enable live Gemini reasoning and SerpAPI search footprint auditing:

Create a `.env` file:
```bash
cp .env.example .env
```

Edit `.env` with your API keys:
```env
GEMINI_API_KEY=your_gemini_api_key_here
SERPAPI_API_KEY=your_serpapi_api_key_here
```

Keys can also be entered or updated dynamically at runtime via the "APIs" link on the web interface.

### Step 5: Start the Application
```bash
python3 app.py
```

Navigate to:
```
http://127.0.0.1:5000
```

---

## 9. API Reference

### Analyze Input
- Method: `POST`
- Endpoint: `/api/analyze`
- Request Payload:
```json
{
  "input_text": "http://paypa1-security-verification.live/signin",
  "gemini_key": "optional_override_key",
  "serpapi_key": "optional_override_key"
}
```
- Response (200 OK):
```json
{
  "status": "success",
  "input_type": "url",
  "analyzed_input": "http://paypa1-security-verification.live/signin",
  "risk_category": "Critical Threat",
  "trust_score": 5,
  "plain_english_warning": "This is a highly dangerous phishing link designed to steal your credentials...",
  "domain_intel": {
    "domain": "paypa1-security-verification.live",
    "status": "Unverified Domain",
    "indexed_results": 51,
    "flags": [
      "Visual homoglyph typosquatting detected: 'paypa1' mimics trademarked brand 'paypal'",
      "Domain uses high-abuse top-level domain (.live)"
    ]
  },
  "psychological_triggers": [
    "Artificial Urgency",
    "Fake Authority / Brand Impersonation"
  ],
  "recommended_precautions": [
    "Do not click the link, open it in a browser, or enter any personal information.",
    "Mark the message as spam or phishing and delete it immediately.",
    "Enable Two-Factor Authentication (2FA) on all your online accounts."
  ],
  "ai_engine": "Google Gemini AI (Live - gemini-2.5-flash)"
}
```

### Get Presets
- Method: `GET`
- Endpoint: `/api/presets`
- Response: Returns the 6 preloaded threat test scenarios.

### System Status
- Method: `GET`
- Endpoint: `/api/status`
- Response: Returns active status of Gemini, SerpAPI, and fallback engines.

### Runtime Key Update
- Method: `POST`
- Endpoint: `/api/save_keys`
- Payload: `{"gemini_key": "...", "serpapi_key": "..."}`

---

## 10. Privacy and Security

- Stateless Processing: User inputs are analyzed transiently and are never logged, stored in databases, or sold.
- Client-Side Key Management: API keys provided through the web modal remain in memory and in the user's local session.
- Secure Defaults: Safe handling of dangerous input strings without executing or rendering remote HTML/JavaScript.

---

## 11. Future Scope and Roadmap

1. Pre-Send Outbound Message Interceptor:
   - Endpoint background agent for mobile (Android/iOS) and desktop (Windows/macOS/Linux).
   - Inspects outbound messages in chat apps (WhatsApp, Telegram, SMS, Slack) and blocks transmission if a malicious link is detected, protecting the user's contacts from infection cascades.
2. Real-Time Clipboard Shield:
   - Detects malicious URLs in the clipboard buffer before the user can paste them into a browser or application.
3. Browser Extension:
   - Zero-latency page inspection verifying search authority before credential entry.

---

## 12. Authors and Credits

Created By AJ and the Team  
Hackathon 2026: Track 1 — Cybersecurity and Digital Trust
