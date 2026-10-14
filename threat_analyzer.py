import re
import urllib.parse
from serp_intel import extract_domain, analyze_domain_footprint
from gemini_analyzer import analyze_with_gemini

class ThreatAnalyzer:
    def __init__(self, gemini_key: str = None, serpapi_key: str = None):
        self.gemini_key = gemini_key
        self.serpapi_key = serpapi_key

    def update_keys(self, gemini_key: str = None, serpapi_key: str = None):
        if gemini_key is not None:
            self.gemini_key = gemini_key.strip() or None
        if serpapi_key is not None:
            self.serpapi_key = serpapi_key.strip() or None

    def detect_input_type(self, text: str) -> str:
        """Classify input as 'url', 'message_with_urls', or 'message_text'."""
        text = text.strip()
        # Single URL check
        if re.match(r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?$", text) and "\n" not in text:
            return "url"
        
        # Check if contains URLs
        urls = re.findall(r"https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+(?:com|in|org|net|xyz|top|live|shop|icu|buzz)(?:/[^\s]*)?", text)
        if urls:
            return "message_with_urls"
        
        return "message_text"

    def extract_first_domain(self, text: str) -> str:
        """Extract primary domain from text or URL."""
        text = text.strip()
        urls = re.findall(r"https?://[^\s]+", text)
        if urls:
            clean_url = urls[0].rstrip(".,;:!?)'\"<>")
            return extract_domain(clean_url)
        
        # Check domain pattern without scheme
        naked = re.findall(r"(?:[a-zA-Z0-9-]+\.)+(?:com|in|org|net|xyz|top|live|shop|icu|buzz|co|io|app|dev)", text)
        if naked:
            clean_naked = naked[0].rstrip(".,;:!?)'\"<>")
            return extract_domain(clean_naked)
        
        # If the input itself is just a domain like 'paypa1.com'
        if "." in text and " " not in text and "\n" not in text:
            return extract_domain(text.rstrip(".,;:!?)'\"<>"))
            
        return ""

    def analyze(self, text: str, user_gemini_key: str = None, user_serpapi_key: str = None) -> dict:
        text = text.strip()
        if not text:
            return {
                "error": "Empty input provided",
                "status": "error"
            }

        gem_key = user_gemini_key or self.gemini_key
        serp_key = user_serpapi_key or self.serpapi_key

        input_type = self.detect_input_type(text)
        primary_domain = self.extract_first_domain(text)

        # 1. Domain & Search Footprint Intelligence (via SerpAPI / Search Authority)
        domain_intel = None
        if primary_domain:
            domain_intel = analyze_domain_footprint(primary_domain, serpapi_key=serp_key)

        # 2. Semantic & Behavioral AI Threat Analysis (via Gemini API / NLP Engine)
        gemini_result = analyze_with_gemini(text, domain_intel=domain_intel, gemini_key=gem_key)

        # 3. Calculate Unified Trust Score (0 to 100)
        # Trust Score is the inverse of threat: High trust = Safe, Low trust = Fake / Dangerous
        threat_score = gemini_result.get("threat_score", 50)
        domain_trust = domain_intel.get("trust_score", 65) if domain_intel else 75

        # Weighted composite score: 55% AI threat analysis + 45% domain trust authority
        if domain_intel and domain_intel.get("domain"):
            composite_trust = int((100 - threat_score) * 0.55 + domain_trust * 0.45)
        else:
            composite_trust = int(100 - threat_score)

        composite_trust = max(2, min(99, composite_trust))

        # Risk Classification & Visual Status
        if composite_trust >= 80:
            trust_verdict = "VERIFIED SAFE"
            risk_category = "Safe"
            verdict_theme = "safe"  # light green accent / white
            badge_icon = "check-circle"
        elif composite_trust >= 45:
            trust_verdict = "SUSPICIOUS / CAUTION"
            risk_category = "Suspicious"
            verdict_theme = "warning"  # amber / grey
            badge_icon = "alert-triangle"
        else:
            trust_verdict = "FAKE / UNSAFE THREAT"
            risk_category = "Critical Threat"
            verdict_theme = "danger"  # dark black/red accent
            badge_icon = "shield-alert"

        # Combine detected patterns and domain evidence
        combined_patterns = []
        if domain_intel and domain_intel.get("flags"):
            combined_patterns.extend(domain_intel["flags"])
        for p in gemini_result.get("suspicious_patterns", []):
            if p not in combined_patterns:
                combined_patterns.append(p)

        return {
            "status": "success",
            "input_type": input_type,
            "analyzed_input": text,
            "trust_score": composite_trust,
            "threat_score": 100 - composite_trust,
            "trust_verdict": trust_verdict,
            "risk_category": risk_category,
            "verdict_theme": verdict_theme,
            "badge_icon": badge_icon,
            "threat_type": gemini_result.get("threat_type", "Digital Threat"),
            "plain_english_warning": gemini_result.get("plain_english_warning", ""),
            "suspicious_patterns": combined_patterns,
            "psychological_triggers": gemini_result.get("psychological_triggers", []),
            "recommended_precautions": gemini_result.get("recommended_precautions", []),
            "domain_intel": domain_intel,
            "ai_engine": gemini_result.get("engine", "Built-in Neural AI"),
            "serp_status": domain_intel.get("status") if domain_intel else "No domain detected",
            "serp_footprint": domain_intel.get("search_footprint") if domain_intel else "N/A"
        }
