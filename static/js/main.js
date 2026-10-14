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

    // 1. Initialize Presets
    async function loadPresets() {
        try {
            const res = await fetch("/api/presets");
            if (res.ok) {
                const presets = await res.json();
                renderPresets(presets);
            }
        } catch (e) {
            console.warn("Using fallback presets");
        }
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

    // 2. Input Handling & Auto-resize
    function autoResizeInput() {
        threatInput.style.height = "auto";
        threatInput.style.height = Math.min(160, Math.max(48, threatInput.scrollHeight)) + "px";
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
                throw new Error("Failed to analyze input.");
            }

            const data = await response.json();
            latestResult = data;
            displayResults(data);
        } catch (err) {
            console.error(err);
            showToast("Analysis encountered an error. Please try again.");
        } finally {
            loadingState.classList.add("hidden");
            btnAnalyze.disabled = false;
        }
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
