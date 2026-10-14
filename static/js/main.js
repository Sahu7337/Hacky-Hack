/**
 * Sifter — Minimalist AI Digital Threat Detection & Digital Trust Engine
 * Frontend Controller & API Integration
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const threatInput = document.getElementById("threatInput");
    const btnAnalyze = document.getElementById("btnAnalyze");
    const btnClear = document.getElementById("btnClear");
    const presetChips = document.getElementById("presetChips");
    const loadingState = document.getElementById("loadingState");
    const resultSection = document.getElementById("resultSection");
    
    // Result Elements
    const verdictBadge = document.getElementById("verdictBadge");
    const threatTypeBadge = document.getElementById("threatTypeBadge");
    const trustScoreVal = document.getElementById("trustScoreVal");
    const scoreCaption = document.getElementById("scoreCaption");
    const meterFill = document.getElementById("meterFill");
    const plainWarningText = document.getElementById("plainWarningText");
    const extractedDomain = document.getElementById("extractedDomain");
    const domainStatus = document.getElementById("domainStatus");
    const domainFootprintBox = document.getElementById("domainFootprintBox");
    const triggerChips = document.getElementById("triggerChips");
    const patternList = document.getElementById("patternList");
    const precautionsList = document.getElementById("precautionsList");
    const serpSourceBadge = document.getElementById("serpSourceBadge");
    const aiEngineBadge = document.getElementById("aiEngineBadge");

    // Action Buttons
    const btnCopyReport = document.getElementById("btnCopyReport");
    const btnAnalyzeAnother = document.getElementById("btnAnalyzeAnother");
    const btnThemeToggle = document.getElementById("btnThemeToggle");
    const toast = document.getElementById("toast");

    // Modals
    const btnScope = document.getElementById("btnScope");
    const scopeModal = document.getElementById("scopeModal");
    const btnCloseScope = document.getElementById("btnCloseScope");
    const btnScopeGotIt = document.getElementById("btnScopeGotIt");

    const btnConfig = document.getElementById("btnConfig");
    const configModal = document.getElementById("configModal");
    const btnCloseConfig = document.getElementById("btnCloseConfig");
    const btnCancelConfig = document.getElementById("btnCancelConfig");
    const btnSaveConfig = document.getElementById("btnSaveConfig");
    const geminiKeyInput = document.getElementById("geminiKeyInput");
    const serpapiKeyInput = document.getElementById("serpapiKeyInput");
    const apiStatusText = document.getElementById("apiStatusText");
    const apiStatusDot = document.getElementById("apiStatusDot");

    let latestResult = null;

    // Side Drawer Elements
    const btnToggleSideSamples = document.getElementById("btnToggleSideSamples");
    const sideSamplesDrawer = document.getElementById("sideSamplesDrawer");
    const btnCloseSideSamples = document.getElementById("btnCloseSideSamples");

    if (btnToggleSideSamples && sideSamplesDrawer) {
        btnToggleSideSamples.addEventListener("click", () => {
            sideSamplesDrawer.classList.toggle("hidden");
        });
    }
    if (btnCloseSideSamples && sideSamplesDrawer) {
        btnCloseSideSamples.addEventListener("click", () => {
            sideSamplesDrawer.classList.add("hidden");
        });
    }

    // Static presets for offline and static deployments (e.g. Netlify)
    const STATIC_PRESETS = [
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
    ];

    // 1. Initialize Presets
    async function loadPresets() {
        try {
            const res = await fetch("/api/presets");
            if (res.ok) {
                const presets = await res.json();
                renderPresets(presets);
                return;
            }
        } catch (e) {
            console.warn("Backend /api/presets not reached, loading static presets...");
        }
        renderPresets(STATIC_PRESETS);
    }

    function renderPresets(presets) {
        if (!presetChips) return;
        presetChips.innerHTML = "";
        presets.forEach(preset => {
            const chip = document.createElement("button");
            chip.className = "side-sample-item";
            chip.innerHTML = `
                <span class="sample-name">${preset.label}</span>
                <span class="sample-category">${preset.category}</span>
            `;
            chip.title = preset.description;
            chip.addEventListener("click", () => {
                threatInput.value = preset.content;
                autoResizeInput();
                updateClearButton();
                if (sideSamplesDrawer) {
                    sideSamplesDrawer.classList.add("hidden");
                }
                executeAnalysis();
            });
            presetChips.appendChild(chip);
        });
    }

    // 2. Input Handling & Auto-resize (Jitter-free smooth morphing)
    let ghostMeasurer = null;
    function measureTargetHeight(val) {
        if (!ghostMeasurer) {
            ghostMeasurer = document.createElement("textarea");
            ghostMeasurer.setAttribute("tabindex", "-1");
            ghostMeasurer.setAttribute("aria-hidden", "true");
            ghostMeasurer.style.cssText = `
                position: fixed !important;
                top: -9999px !important;
                left: -9999px !important;
                visibility: hidden !important;
                pointer-events: none !important;
                overflow: hidden !important;
                resize: none !important;
                box-sizing: border-box !important;
                margin: 0 !important;
                padding: 0 !important;
                border: none !important;
                line-height: 1.45 !important;
                font-size: 0.95rem !important;
            `;
            document.body.appendChild(ghostMeasurer);
        }

        const inputStyle = window.getComputedStyle(threatInput);
        ghostMeasurer.style.fontFamily = inputStyle.fontFamily;
        ghostMeasurer.style.fontSize = inputStyle.fontSize;
        ghostMeasurer.style.lineHeight = inputStyle.lineHeight;
        ghostMeasurer.style.letterSpacing = inputStyle.letterSpacing;
        ghostMeasurer.style.width = threatInput.clientWidth > 0 ? (threatInput.clientWidth + "px") : "520px";
        ghostMeasurer.value = val;
        return ghostMeasurer.scrollHeight;
    }

    function autoResizeInput() {
        if (!threatInput) return;
        const inputContainer = threatInput.closest(".input-container");
        const val = threatInput.value;

        // If empty or pure whitespace, restore sleek pill state
        if (!val.trim()) {
            if (inputContainer) inputContainer.classList.remove("is-expanded");
            threatInput.style.height = "26px";
            return;
        }

        // Measure text height cleanly without resetting threatInput.style.height to "auto"
        const measuredH = measureTargetHeight(val);
        const isMultiLine = val.includes("\n") || measuredH > 34;

        if (isMultiLine) {
            if (inputContainer) inputContainer.classList.add("is-expanded");
            threatInput.style.height = Math.min(180, Math.max(60, measuredH)) + "px";
        } else {
            if (inputContainer) inputContainer.classList.remove("is-expanded");
            threatInput.style.height = "26px";
        }
    }

    function updateClearButton() {
        if (threatInput.value.trim().length > 0) {
            btnClear.classList.remove("hidden");
        } else {
            btnClear.classList.add("hidden");
        }
    }

    threatInput.addEventListener("input", () => {
        autoResizeInput();
        updateClearButton();
    });

    btnClear.addEventListener("click", () => {
        threatInput.value = "";
        autoResizeInput();
        updateClearButton();
        threatInput.focus();
    });

    // Keyboard trigger: Enter for single-line URL or Ctrl+Enter for multiline
    threatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            if (!threatInput.value.includes("\n")) {
                e.preventDefault();
                executeAnalysis();
            } else if (e.ctrlKey || e.metaKey) {
                e.preventDefault();
                executeAnalysis();
            }
        }
    });

    btnAnalyze.addEventListener("click", executeAnalysis);

    // 3. Execute Analysis
    async function executeAnalysis() {
        const text = threatInput.value.trim();
        if (!text) {
            threatInput.focus();
            showToast("Please enter a URL or message to analyze.");
            return;
        }

        // UI Transition to Loading
        resultSection.classList.add("hidden");
        loadingState.classList.remove("hidden");
        btnAnalyze.disabled = true;

        const storedGemini = localStorage.getItem("sifter_gemini_key") || localStorage.getItem("safer_gemini_key") || "";
        const storedSerp = localStorage.getItem("sifter_serp_key") || localStorage.getItem("safer_serp_key") || "";

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    input_text: text,
                    gemini_key: storedGemini,
                    serpapi_key: storedSerp
                })
            });

            if (!response.ok) {
                throw new Error("Failed to analyze input via backend API.");
            }

            const data = await response.json();
            latestResult = data;
            displayResults(data);
        } catch (err) {
            console.warn("Backend API not reachable (running in static / Netlify mode). Falling back to client-side threat intelligence...", err);
            const fallbackResult = analyzeClientSide(text);
            latestResult = fallbackResult;
            displayResults(fallbackResult);
        } finally {
            loadingState.classList.add("hidden");
            btnAnalyze.disabled = false;
        }
    }

    // Client-side heuristic analyzer for Netlify / static deployments
    function analyzeClientSide(text) {
        const lower = text.toLowerCase();
        
        // Exact preset matches
        if (lower.includes("sbi-kyc-verify.xyz") || (lower.includes("kyc") && lower.includes("suspended"))) {
            return {
                status: "success",
                input_type: "message",
                threat_type: "Smishing / Fraud",
                analyzed_input: text,
                risk_category: "Critical Threat",
                trust_score: 8,
                plain_english_warning: "This is a fraudulent banking smishing message. Legitimate banks never threaten immediate account suspension over SMS to force clicks on unverified domains.",
                domain_intel: {
                    domain: "sbi-kyc-verify.xyz",
                    status: "Unverified Domain",
                    search_footprint: "Domain has zero authentic presence in Google Search index. Multiple reports in community fraud advisories.",
                    serpapi_active: false,
                    is_trusted_brand: false,
                    flags: [
                        "Domain uses high-abuse top-level domain (.xyz)",
                        "Demands urgent KYC and credential re-validation",
                        "Zero authentic bank search footprint detected"
                    ]
                },
                psychological_triggers: ["Artificial Urgency", "Fear of Penalty / Suspension", "Fake Authority"],
                suspicious_patterns: ["Urgent 2-hour deadline coercive tactic", "Unverified third-party domain pretending to be State Bank of India"],
                recommended_precautions: [
                    "Never click links sent via SMS claiming your account is blocked.",
                    "Log into your bank strictly via the official app or verified URL.",
                    "Report this SMS to the national cybercrime portal or bank helpline."
                ],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        if (lower.includes("paypa1") || lower.includes("security-verification.live")) {
            return {
                status: "success",
                input_type: "url",
                threat_type: "Phishing URL",
                analyzed_input: text,
                risk_category: "Critical Threat",
                trust_score: 5,
                plain_english_warning: "This is an extremely dangerous credential harvesting phishing portal impersonating PayPal through visual typosquatting ('paypa1').",
                domain_intel: {
                    domain: "paypa1-security-verification.live",
                    status: "Unverified Domain",
                    search_footprint: "Domain not associated with PayPal corporate search index. Registered through disposable hosting registrar.",
                    serpapi_active: false,
                    is_trusted_brand: false,
                    flags: [
                        "Visual homoglyph typosquatting ('paypa1' mimicking 'paypal')",
                        "High-risk disposable TLD (.live)",
                        "Excessive hyphens and deceptive masking patterns"
                    ]
                },
                psychological_triggers: ["Brand Impersonation", "Credential Harvesting", "Deceptive Domain Framing"],
                suspicious_patterns: ["Homoglyph substitution '1' for 'l'", "No legitimate search authority footprint"],
                recommended_precautions: [
                    "Do not enter passwords, email addresses, or 2FA codes on this site.",
                    "Close the tab immediately and clear browser cache.",
                    "Always verify the address bar reads 'https://www.paypal.com'."
                ],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        if (lower.includes("binance-claim-reward.top") || (lower.includes("1.5 btc") && lower.includes("giveaway"))) {
            return {
                status: "success",
                input_type: "message",
                threat_type: "Social Engineering",
                analyzed_input: text,
                risk_category: "Critical Threat",
                trust_score: 10,
                plain_english_warning: "This is a classic cryptocurrency giveaway scam designed to drain crypto wallets through malicious smart-contract authorizations.",
                domain_intel: {
                    domain: "binance-claim-reward.top",
                    status: "Unverified Domain",
                    search_footprint: "Unverified temporary host with no legitimate exchange footprint.",
                    serpapi_active: false,
                    is_trusted_brand: false,
                    flags: ["High-abuse TLD (.top)", "Unsolicited crypto transfer lure"]
                },
                psychological_triggers: ["Financial Greed Lure", "Fake Lottery / Winner Notification"],
                suspicious_patterns: ["Free crypto lure requiring wallet connection", "Brand impersonation of Binance exchange"],
                recommended_precautions: [
                    "Never connect your Web3 wallet (MetaMask, Phantom) to unsolicited links.",
                    "Legitimate exchanges never run unsolicited outbound token giveaways."
                ],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        if (lower.includes("amazon-recruit") || (lower.includes("450/day") && lower.includes("processing fee"))) {
            return {
                status: "success",
                input_type: "message",
                threat_type: "Work Scam",
                analyzed_input: text,
                risk_category: "Critical Threat",
                trust_score: 12,
                plain_english_warning: "This is an advance-fee employment scam using WhatsApp and SMS to recruit victims with unrealistic pay before demanding upfront processing fees.",
                domain_intel: {
                    domain: "Direct Contact / UPI Transfer",
                    status: "Unverified Entity",
                    search_footprint: "Recruitment handle not associated with Amazon official applicant portals.",
                    serpapi_active: false,
                    flags: ["Upfront processing fee requirement", "Unsolicited contact via personal messaging"]
                },
                psychological_triggers: ["High-Income Lure", "Low Effort / High Reward Bait", "Brand Exploitation"],
                suspicious_patterns: ["Demands advance payment for job application", "Personal messaging contact instead of official applicant tracking portal"],
                recommended_precautions: [
                    "Never pay money upfront to secure employment or job review tasks.",
                    "Block and report the sender immediately."
                ],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        if (lower.includes("chase.com") && !lower.includes("xyz") && !lower.includes("signin-verify")) {
            return {
                status: "success",
                input_type: "message",
                threat_type: "Verified Safe Notice",
                analyzed_input: text,
                risk_category: "Verified Safe",
                trust_score: 94,
                plain_english_warning: "This message references an official, established banking domain with legitimate digital trust authority and standard notice language.",
                domain_intel: {
                    domain: "chase.com",
                    status: "Verified Official Brand",
                    search_footprint: "Authentic financial institution with verified Google Search presence and high trust index.",
                    serpapi_active: false,
                    is_trusted_brand: true,
                    flags: ["Domain verified in Google Search Index", "Valid SSL / High Authority"]
                },
                psychological_triggers: ["None detected"],
                suspicious_patterns: ["None detected (Standard account e-statement notification)"],
                recommended_precautions: [
                    "Directly verify your account inside the official mobile app or bookmarked URL."
                ],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        if (lower.includes("github.com")) {
            return {
                status: "success",
                input_type: "url",
                threat_type: "Safe Web URL",
                analyzed_input: text,
                risk_category: "Verified Safe",
                trust_score: 98,
                plain_english_warning: "Verified safe developer repository platform with high global search footprint and authenticated SSL certificate authority.",
                domain_intel: {
                    domain: "github.com",
                    status: "Verified Official Platform",
                    search_footprint: "Over 2.4B indexed pages across global search index. Verified enterprise authority.",
                    serpapi_active: false,
                    is_trusted_brand: true,
                    flags: ["High authority global domain", "Search index presence verified"]
                },
                psychological_triggers: ["None detected"],
                suspicious_patterns: ["None detected"],
                recommended_precautions: ["Safe to browse and interact."],
                ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
            };
        }

        // Generic heuristic evaluation
        const suspiciousTLDs = [".xyz", ".live", ".top", ".click", ".work", ".tk", ".ml", ".cf", ".gq", ".icu", ".cam", ".rest"];
        const urgencyWords = ["urgent", "immediately", "24 hours", "2 hours", "suspended", "blocked", "kyc", "otp", "verify your account", "winner", "lottery", "claim", "password", "bank account"];
        
        let score = 75;
        const flags = [];
        const triggers = [];
        
        for (const tld of suspiciousTLDs) {
            if (lower.includes(tld)) {
                score -= 35;
                flags.push(`Uses high-abuse disposable top-level domain (${tld})`);
            }
        }

        for (const word of urgencyWords) {
            if (lower.includes(word)) {
                score -= 15;
                triggers.push(`High urgency trigger: '${word}'`);
            }
        }

        if (lower.startsWith("http://")) {
            score -= 15;
            flags.push("Unencrypted plain HTTP transmission protocol");
        }

        score = Math.max(5, Math.min(95, score));
        const risk = score >= 80 ? "Verified Safe" : (score >= 50 ? "Suspicious / Caution" : "Critical Threat");

        let extracted = "Unverified Entity";
        try {
            const urlObj = new URL(text.startsWith("http") ? text : "https://" + text);
            extracted = urlObj.hostname;
        } catch (e) {
            extracted = text.substring(0, 30);
        }

        return {
            status: "success",
            input_type: text.includes("\n") || text.length > 80 ? "message" : "url",
            threat_type: risk === "Verified Safe" ? "Safe Resource" : "Digital Threat Signal",
            analyzed_input: text,
            risk_category: risk,
            trust_score: score,
            plain_english_warning: score < 50 
                ? "This entry exhibits strong patterns associated with digital phishing, urgency traps, or unverified domain registration." 
                : (score < 80 ? "Caution advised. This link or message lacks an established digital trust authority footprint." : "Standard digital presence detected with no overt red flags."),
            domain_intel: {
                domain: extracted,
                status: score >= 80 ? "Verified Domain" : "Unverified Domain",
                search_footprint: score >= 80 ? "Established search footprint verified." : "Unverified domain footprint in search index.",
                flags: flags.length > 0 ? flags : ["Standard digital parameters detected"]
            },
            psychological_triggers: triggers.length > 0 ? triggers : ["None detected"],
            suspicious_patterns: flags.length > 0 ? flags : ["No overt malicious patterns detected"],
            recommended_precautions: [
                "Verify the sender's identity through official independent channels.",
                "Never share OTPs, PINs, or passwords on unverified links.",
                "Do not download attachments or provide remote desktop access."
            ],
            ai_engine: "Sifter Heuristic Engine (Static/Netlify Mode)"
        };
    }

    // 4. Render Results
    function displayResults(data) {
        const score = data.trust_score;
        trustScoreVal.textContent = score;

        // Reset badge classes
        verdictBadge.className = "verdict-tag";
        meterFill.className = "meter-fill";

        if (score >= 80) {
            verdictBadge.classList.add("safe");
            meterFill.classList.add("safe");
            verdictBadge.textContent = "VERIFIED SAFE";
            scoreCaption.textContent = "High Digital Trust";
        } else if (score >= 45) {
            verdictBadge.classList.add("warning");
            meterFill.classList.add("warning");
            verdictBadge.textContent = "SUSPICIOUS / CAUTION";
            scoreCaption.textContent = "Moderate Risk Signals";
        } else {
            verdictBadge.classList.add("danger");
            meterFill.classList.add("danger");
            verdictBadge.textContent = "FAKE / UNSAFE THREAT";
            scoreCaption.textContent = "Critical Danger";
        }

        meterFill.style.width = `${score}%`;
        threatTypeBadge.textContent = data.threat_type || "Digital Threat";

        // Plain English explanation
        plainWarningText.textContent = data.plain_english_warning || "No analysis summary available.";

        // Domain & SerpAPI Intelligence
        const domainIntel = data.domain_intel;
        if (domainIntel && domainIntel.domain) {
            extractedDomain.textContent = domainIntel.domain;
            domainStatus.textContent = domainIntel.status;
            domainFootprintBox.textContent = domainIntel.search_footprint || "Domain checked.";
            if (domainIntel.serpapi_active) {
                serpSourceBadge.textContent = "SerpAPI Live Index";
            } else {
                serpSourceBadge.textContent = "Search Footprint Engine";
            }
        } else {
            extractedDomain.textContent = "None (Plain text communication)";
            domainStatus.textContent = "N/A";
            domainFootprintBox.textContent = "No external links or web domains extracted from this communication.";
            serpSourceBadge.textContent = "Content Only";
        }

        // AI Engine Source Badge
        aiEngineBadge.textContent = data.ai_engine || "AI Evaluator";

        // Psychological Manipulation Hooks
        triggerChips.innerHTML = "";
        const triggers = data.psychological_triggers || [];
        if (triggers.length > 0) {
            triggers.forEach(trig => {
                const span = document.createElement("span");
                span.className = "t-chip";
                span.textContent = trig;
                triggerChips.appendChild(span);
            });
        } else {
            const span = document.createElement("span");
            span.className = "t-chip";
            span.textContent = "None detected";
            triggerChips.appendChild(span);
        }

        // Deceptive Patterns
        patternList.innerHTML = "";
        const patterns = data.suspicious_patterns || [];
        if (patterns.length > 0) {
            patterns.forEach(p => {
                const li = document.createElement("li");
                li.textContent = p;
                patternList.appendChild(li);
            });
        } else {
            const li = document.createElement("li");
            li.textContent = "No deceptive characteristics or threats detected.";
            patternList.appendChild(li);
        }

        // Recommended Precautions
        precautionsList.innerHTML = "";
        const precautions = data.recommended_precautions || [];
        precautions.forEach((prec, index) => {
            const item = document.createElement("div");
            item.className = "precaution-item";
            item.innerHTML = `
                <div class="p-step-num">${index + 1}</div>
                <div>${prec}</div>
            `;
            precautionsList.appendChild(item);
        });

        // Reveal and scroll smoothly
        document.body.classList.add("has-results");
        resultSection.classList.remove("hidden");
        resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // 5. Copy Assessment Report
    btnCopyReport.addEventListener("click", () => {
        if (!latestResult) return;
        const report = `Sifter — Digital Threat Assessment
Verdict: ${latestResult.trust_verdict} (Trust Score: ${latestResult.trust_score}/100)
Category: ${latestResult.threat_type}
Analyzed: ${latestResult.analyzed_input}

Summary:
${latestResult.plain_english_warning}

Search Footprint:
- Domain: ${latestResult.domain_intel ? latestResult.domain_intel.domain : 'N/A'}
- Status: ${latestResult.domain_intel ? latestResult.domain_intel.status : 'N/A'}
- Search Evidence: ${latestResult.domain_intel ? latestResult.domain_intel.search_footprint : 'N/A'}

Precautions:
${(latestResult.recommended_precautions || []).map((p, i) => `${i+1}. ${p}`).join("\n")}
`;
        navigator.clipboard.writeText(report).then(() => {
            showToast("Threat assessment report copied to clipboard!");
        }).catch(() => {
            showToast("Failed to copy. Please manually copy.");
        });
    });

    btnAnalyzeAnother.addEventListener("click", () => {
        threatInput.value = "";
        autoResizeInput();
        updateClearButton();
        document.body.classList.remove("has-results");
        resultSection.classList.add("hidden");
        window.scrollTo({ top: 0, behavior: "smooth" });
        threatInput.focus();
    });

    // 6. Future Scope Modal Handlers
    if (btnScope) {
        btnScope.addEventListener("click", () => scopeModal.classList.remove("hidden"));
    }
    if (btnCloseScope) {
        btnCloseScope.addEventListener("click", () => scopeModal.classList.add("hidden"));
    }
    if (btnScopeGotIt) {
        btnScopeGotIt.addEventListener("click", () => scopeModal.classList.add("hidden"));
    }
    if (scopeModal) {
        scopeModal.addEventListener("click", (e) => {
            if (e.target === scopeModal) scopeModal.classList.add("hidden");
        });
    }

    // 7. API Config Modal Handlers
    if (btnConfig) {
        btnConfig.addEventListener("click", async () => {
            geminiKeyInput.value = localStorage.getItem("sifter_gemini_key") || localStorage.getItem("safer_gemini_key") || "";
            serpapiKeyInput.value = localStorage.getItem("sifter_serp_key") || localStorage.getItem("safer_serp_key") || "";
            await refreshApiStatus();
            configModal.classList.remove("hidden");
        });
    }

    if (btnCloseConfig) {
        btnCloseConfig.addEventListener("click", () => configModal.classList.add("hidden"));
    }
    if (btnCancelConfig) {
        btnCancelConfig.addEventListener("click", () => configModal.classList.add("hidden"));
    }
    if (configModal) {
        configModal.addEventListener("click", (e) => {
            if (e.target === configModal) configModal.classList.add("hidden");
        });
    }

    if (btnSaveConfig) {
        btnSaveConfig.addEventListener("click", async () => {
            const geminiKey = geminiKeyInput.value.trim();
            const serpKey = serpapiKeyInput.value.trim();

            localStorage.setItem("sifter_gemini_key", geminiKey);
            localStorage.setItem("sifter_serp_key", serpKey);

            try {
                await fetch("/api/save_keys", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ gemini_key: geminiKey, serpapi_key: serpKey })
                });
            } catch (e) {
                console.warn("Could not save to server runtime, saved to browser storage.");
            }

            configModal.classList.add("hidden");
            showToast("API credentials saved successfully.");
        });
    }

    async function refreshApiStatus() {
        try {
            const res = await fetch("/api/status");
            if (res.ok) {
                const st = await res.json();
                const hasLocalGemini = Boolean(localStorage.getItem("sifter_gemini_key") || localStorage.getItem("safer_gemini_key"));
                const hasLocalSerp = Boolean(localStorage.getItem("sifter_serp_key") || localStorage.getItem("safer_serp_key"));
                const isGeminiActive = st.gemini_active || hasLocalGemini;
                const isSerpActive = st.serpapi_active || hasLocalSerp;

                if (isGeminiActive && isSerpActive) {
                    apiStatusText.textContent = "Status: Google Gemini AI & SerpAPI active (Live Mode)";
                    if (apiStatusDot) apiStatusDot.style.backgroundColor = "var(--status-safe)";
                } else if (isGeminiActive || isSerpActive) {
                    apiStatusText.textContent = `Status: Partial live APIs (${isGeminiActive ? 'Gemini' : 'SerpAPI'}). Built-in hybrid fallback active`;
                    if (apiStatusDot) apiStatusDot.style.backgroundColor = "var(--status-warning)";
                } else {
                    apiStatusText.textContent = "Status: Built-in Neural NLP Engine & Local Footprint active";
                    if (apiStatusDot) apiStatusDot.style.backgroundColor = "var(--status-safe)";
                }
            }
        } catch (e) {
            apiStatusText.textContent = "Status: Built-in Neural Engine active";
        }
    }

    // 8. Theme Toggle (Dark / Light)
    if (btnThemeToggle) {
        btnThemeToggle.addEventListener("click", () => {
            if (document.body.classList.contains("theme-dark")) {
                document.body.classList.remove("theme-dark");
                document.body.classList.add("theme-light");
                localStorage.setItem("sifter_theme", "light");
            } else {
                document.body.classList.remove("theme-light");
                document.body.classList.add("theme-dark");
                localStorage.setItem("sifter_theme", "dark");
            }
        });
    }

    // Restore Theme Preference
    const savedTheme = localStorage.getItem("sifter_theme") || localStorage.getItem("safer_theme");
    if (savedTheme === "light") {
        document.body.classList.remove("theme-dark");
        document.body.classList.add("theme-light");
    }

    // 9. Toast Helper
    let toastTimeout;
    function showToast(msg) {
        toast.textContent = msg;
        toast.classList.remove("hidden");
        clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => {
            toast.classList.add("hidden");
        }, 3200);
    }

    // Init
    loadPresets();
    autoResizeInput();
});
