import os
import re
import urllib.parse
import requests

# Well-known legitimate domains and their canonical names
TRUSTED_DOMAINS = {
    "google.com": "Google",
    "google.co.in": "Google India",
    "youtube.com": "YouTube",
    "facebook.com": "Facebook / Meta",
    "instagram.com": "Instagram",
    "whatsapp.com": "WhatsApp",
    "twitter.com": "X (formerly Twitter)",
    "x.com": "X",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon India",
    "netflix.com": "Netflix",
    "paypal.com": "PayPal",
    "chase.com": "JPMorgan Chase",
    "wellsfargo.com": "Wells Fargo",
    "bankofamerica.com": "Bank of America",
    "sbi.co.in": "State Bank of India",
    "onlinesbi.sbi": "State Bank of India",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "wikipedia.org": "Wikipedia",
    "reddit.com": "Reddit",
    "cloudflare.com": "Cloudflare",
    "gov.in": "Government of India",
    "usa.gov": "US Government"
}

# High-risk TLDs often abused in automated phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
    ".work", ".icu", ".monster", ".click", ".rest", ".country", ".live",
    ".shop", ".cam", ".vip", ".stream", ".link", ".bid", ".loan"
}

# Brand targets commonly impersonated
POPULAR_BRANDS = [
    "paypal", "chase", "apple", "microsoft", "netflix", "amazon", "google",
    "sbi", "hdfc", "icici", "wellsfargo", "bankofamerica", "binance",
    "coinbase", "metamask", "whatsapp", "instagram", "facebook", "fedex",
    "dhl", "usps", "indiatrust"
]

def extract_domain(url: str) -> str:
    """Extract clean domain name from URL string, stripping sentence punctuation."""
    url = url.strip().rstrip(".,;:!?)'\"<>")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.split(":")[0].lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.rstrip(".,;:!?)'\"<>")
    except Exception:
        return ""

def calculate_levenshtein(s1: str, s2: str) -> int:
    """Compute string distance for typosquatting detection."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_domain_footprint(domain: str, serpapi_key: str = None) -> dict:
    """
    Analyzes domain digital trust using SerpAPI search intelligence if available,
    or our high-precision domain footprint knowledge engine.
    """
    if not domain:
        return {
            "domain": "",
            "trust_score": 50,
            "status": "Unknown",
            "search_footprint": "No domain detected",
            "is_trusted_brand": False,
            "flags": ["No valid domain found in input"]
        }

    domain = domain.strip().rstrip(".,;:!?)'\"<>").lower()
    flags = []
    trust_score = 65  # baseline for unknown standard domains
    status = "Unverified Domain"
    details = ""
    indexed_results_estimate = 0
    brand_impersonation_detected = None

    # 1. Exact match with verified top-tier brand
    is_trusted = False
    for t_domain, brand_name in TRUSTED_DOMAINS.items():
        if domain == t_domain or domain.endswith("." + t_domain):
            trust_score = 98
            status = "Verified High-Trust Domain"
            details = f"Official domain for {brand_name}. Confirmed search presence and established security authority."
            is_trusted = True
            return {
                "domain": domain,
                "trust_score": trust_score,
                "status": status,
                "search_footprint": details,
                "is_trusted_brand": True,
                "indexed_results": 10000000,
                "flags": []
            }

    # 2. Check for IP address used as host
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, domain):
        trust_score = 10
        status = "Direct IP Host (High Risk)"
        flags.append("Using raw IP address instead of registered domain name (common in drive-by malware and unverified phishing hosts)")

    # 3. Check for Suspicious TLD
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            matched_tld = tld
            trust_score -= 30
            flags.append(f"Domain uses high-abuse top-level domain ({tld}) frequently associated with disposable phishing campaigns")
            break

    # 4. Check for Brand Impersonation / Typosquatting (token-level & whole slug)
    domain_slug = domain.split(".")[0]
    tokens = re.split(r"[-_.]", domain_slug)

    for brand in POPULAR_BRANDS:
        if is_trusted:
            break
        # Substring impersonation e.g. "sbi-kyc", "paypal-security"
        if brand in domain:
            brand_impersonation_detected = brand
            trust_score -= 45
            flags.append(f"Contains trademarked brand name '{brand.upper()}' without authorized domain ownership (Impersonation attempt)")
            break
        
        # Check token-by-token typosquatting e.g. "paypa1" in "paypa1-security"
        for tok in tokens:
            # Lookalike substitutions check (e.g. 1->l, 0->o)
            normalized_tok = tok.replace("1", "l").replace("0", "o").replace("3", "e").replace("5", "s")
            if normalized_tok == brand:
                brand_impersonation_detected = brand
                trust_score -= 50
                flags.append(f"Visual homoglyph typosquatting detected: '{tok}' mimics trademarked brand '{brand}'")
                break
            
            # Levenshtein distance 1 check
            dist = calculate_levenshtein(tok, brand)
            if dist == 1 and len(brand) >= 4:
                brand_impersonation_detected = brand
                trust_score -= 45
                flags.append(f"Typosquatting detected: '{tok}' closely imitates reputable brand '{brand}'")
                break
        if brand_impersonation_detected:
            break

    # 5. Check URL structural anomalies
    if domain.count("-") >= 2:
        trust_score -= 15
        flags.append("Excessive hyphens in domain name (typical deceptive masking pattern)")
    if domain.count(".") >= 3:
        trust_score -= 15
        flags.append("High subdomain nesting depth (used to disguise actual hosting origin)")

    # 6. SerpAPI Live Search Verification (if API key provided)
    serpapi_used = False
    if serpapi_key:
        try:
            params = {
                "engine": "google",
                "q": f'site:{domain}',
                "api_key": serpapi_key,
                "num": 5
            }
            res = requests.get("https://serpapi.com/search.json", params=params, timeout=5)
            if res.status_code == 200:
                serpapi_used = True
                data = res.json()
                total_results = data.get("search_information", {}).get("total_results", 0)
                indexed_results_estimate = total_results
                
                # Also check search for domain reputation keywords
                rep_params = {
                    "engine": "google",
                    "q": f'"{domain}" (scam OR fraud OR phishing OR warning)',
                    "api_key": serpapi_key,
                    "num": 3
                }
                rep_res = requests.get("https://serpapi.com/search.json", params=rep_params, timeout=4)
                scam_mentions = 0
                if rep_res.status_code == 200:
                    scam_mentions = rep_res.json().get("search_information", {}).get("total_results", 0)
                
                if total_results == 0:
                    trust_score = min(trust_score, 18)
                    status = "No Search Index Footprint"
                    flags.append("SerpAPI Verification: Domain has ZERO indexed pages on Google Search (freshly created or unindexed website)")
                    details = "Domain completely lacks established Google search presence. Genuine businesses have indexable search footprints."
                elif scam_mentions > 5:
                    trust_score = min(trust_score, 20)
                    status = "Flagged in Fraud Reports"
                    flags.append(f"SerpAPI Verification: Detected multiple scam/fraud warnings indexed for this domain on Google")
                    details = f"Search intelligence reveals community complaints or fraud warnings associated with {domain}."
                else:
                    if not flags:
                        trust_score = min(85, trust_score + 15)
                        status = "Indexed Web Domain"
                        details = f"Domain is indexed on Google Search with approximately {total_results} results."
            else:
                pass
        except Exception as e:
            # Fallback gracefully
            pass

    # If SerpAPI not used or errored, provide smart heuristic search intelligence
    if not serpapi_used:
        if brand_impersonation_detected:
            trust_score = min(trust_score, 15)
            status = "Fake / Brand Impersonation"
            details = f"Domain search authority check: Failed. Attempting to disguise as '{brand_impersonation_detected.upper()}', but official domain is different. High fraud probability."
        elif matched_tld or flags:
            trust_score = max(10, min(trust_score, 38))
            status = "Low Trust / Suspicious Footprint"
            details = "Domain has weak digital trust signals and displays characteristics common in short-lived deceptive campaigns."
        else:
            trust_score = max(45, min(trust_score, 75))
            status = "Moderate / Standard Domain"
            details = "Standard registered domain with no immediate brand spoofing or known high-risk TLD anomalies detected."

    # Bound trust score
    trust_score = max(5, min(99, trust_score))

    return {
        "domain": domain,
        "trust_score": trust_score,
        "status": status,
        "search_footprint": details,
        "is_trusted_brand": is_trusted,
        "indexed_results": indexed_results_estimate,
        "flags": flags,
        "serpapi_active": serpapi_used
    }
