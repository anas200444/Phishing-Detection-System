document.addEventListener("DOMContentLoaded", () => {
    const themeToggle = document.getElementById("theme-toggle");
    const body = document.body;

    if (themeToggle) {
        const themeIcon = themeToggle.querySelector("i");
        themeToggle.addEventListener("click", () => {
            body.classList.toggle("dark-mode");
            if (themeIcon) {
                if (body.classList.contains("dark-mode")) {
                    themeIcon.classList.replace("fa-moon", "fa-sun");
                } else {
                    themeIcon.classList.replace("fa-sun", "fa-moon");
                }
            }
        });
    }

    const sidebarToggle = document.getElementById("sidebar-toggle");
    if (sidebarToggle) {
        sidebarToggle.addEventListener("click", () => {
            if (window.innerWidth <= 760) {
                body.classList.toggle("sidebar-open");
            } else {
                body.classList.toggle("sidebar-collapsed");
            }
        });
    }

    const analyzeBtn = document.getElementById("analyze-btn");
    const targetInput = document.getElementById("target-input");
    const resultsContainer = document.getElementById("results-container");
    const clearBtn = document.getElementById("clear-btn");

    const statusIconBox = document.getElementById("status-icon-box");
    const statusIcon = document.getElementById("status-icon");
    const statusBadge = document.getElementById("status-badge");
    const confidenceText = document.getElementById("confidence-text");
    const detailsList = document.getElementById("details-list");

    const originalAnalyzeText = analyzeBtn ? analyzeBtn.textContent.trim() : "Analyze";

    function setButtonLoading(isLoading) {
        if (!analyzeBtn) return;
        analyzeBtn.disabled = isLoading;
        analyzeBtn.textContent = isLoading ? "Analyzing..." : originalAnalyzeText;
    }

    function appendDetailItem(iconClass, text, isDanger = false, customColor = null) {
        if (!detailsList) return;

        const li = document.createElement("li");
        if (isDanger) li.className = "danger-item";

        const icon = document.createElement("i");
        icon.className = iconClass;
        if (customColor) icon.style.color = customColor;

        const span = document.createElement("span");
        span.innerHTML = text;

        li.appendChild(icon);
        li.appendChild(span);
        detailsList.appendChild(li);
    }

    function renderResults(data, inputVal) {
        if (!resultsContainer || !statusIconBox || !statusIcon || !statusBadge || !detailsList) return;

        const isSafe = Boolean(data.is_safe);

        if (isSafe) {
            resultsContainer.style.borderColor = "var(--safe-border)";
            statusIconBox.className = "icon-circle safe-icon";
            statusIcon.className = "fas fa-check";
            statusBadge.className = "badge badge-safe";
        } else {
            resultsContainer.style.borderColor = "var(--danger-border)";
            statusIconBox.className = "icon-circle danger-icon";
            statusIcon.className = "fas fa-times";
            statusBadge.className = "badge badge-danger";
        }

        statusBadge.textContent = data.status || (isSafe ? "Safe" : "Threat Detected");

        if (confidenceText) {
            confidenceText.textContent = data.confidence !== undefined ? `Evidence Confidence: ${data.confidence}` : "";
        }

        const threatTop = document.getElementById("threat-top-dashboard");
        const threatBottom = document.getElementById("threat-bottom-dashboard");
        
        if (threatTop && data.threat_score !== undefined) {
            threatTop.classList.remove("hidden");
            
            const scoreNum = document.getElementById("score-number");
            const scoreFill = document.getElementById("threat-score-fill");
            const score = data.threat_score;
            
            scoreNum.textContent = score;
            scoreFill.style.width = `${score}%`;
            
            if (score < 30) {
                scoreNum.style.color = "var(--safe-text)";
                scoreFill.style.backgroundColor = "var(--safe-text)";
                scoreFill.style.boxShadow = "0 0 10px var(--safe-text)";
            } else if (score < 70) {
                scoreNum.style.color = "var(--orange)";
                scoreFill.style.backgroundColor = "var(--orange)";
                scoreFill.style.boxShadow = "0 0 10px var(--orange)";
            } else {
                scoreNum.style.color = "var(--danger-text)";
                scoreFill.style.backgroundColor = "var(--danger-text)";
                scoreFill.style.boxShadow = "0 0 10px var(--danger-text)";
            }

            // Fix: Use classList.remove instead of overwriting className to preserve base UI structure
            document.querySelectorAll(".matrix-cell").forEach(cell => {
                cell.classList.remove("active", "active-note", "active-low", "active-med", "active-high", "active-critical");
            });
            
            const targetConfidence = data.threat_confidence || data.likelihood || 1;
            const targetHarm = data.potential_harm || data.impact || 1;
            const activeCell = document.getElementById(`cell-${targetConfidence}-${targetHarm}`);
            
            if (activeCell) {
                let riskClass = "active-low";
                
                // Map the backend OWASP severity strictly to the UI layer
                if (data.risk_label === "Critical") {
                    riskClass = "active-critical";
                } else if (data.risk_label === "High") {
                    riskClass = "active-high";
                } else if (data.risk_label === "Medium") {
                    riskClass = "active-med";
                } else if (data.risk_label === "Note") {
                    riskClass = "active-note";
                }
                
                activeCell.classList.add("active", riskClass);
            }

            const impactList = document.getElementById("ai-impact-list");
            const counterList = document.getElementById("ai-countermeasures-list");
            
            if (impactList) impactList.innerHTML = "";
            if (counterList) counterList.innerHTML = "";

            const hasAiData = (data.ai_impact && data.ai_impact.length > 0) || 
                              (data.ai_countermeasures && data.ai_countermeasures.length > 0);

            if (hasAiData && threatBottom) {
                threatBottom.classList.remove("hidden");

                if (data.ai_impact && data.ai_impact.length > 0 && impactList) {
                    data.ai_impact.forEach(impact => {
                        const li = document.createElement("li");
                        li.className = score >= 70 ? "high-impact" : "";
                        li.innerHTML = `<i class="fas fa-circle"></i><span>${impact}</span>`;
                        impactList.appendChild(li);
                    });
                }

                if (data.ai_countermeasures && data.ai_countermeasures.length > 0 && counterList) {
                    data.ai_countermeasures.forEach(cm => {
                        const li = document.createElement("li");
                        li.innerHTML = `<i class="far fa-check-circle"></i><span>${cm}</span>`;
                        counterList.appendChild(li);
                    });
                }
            } else if (threatBottom) {
                threatBottom.classList.add("hidden");
            }
            
        } else {
            if (threatTop) threatTop.classList.add("hidden");
            if (threatBottom) threatBottom.classList.add("hidden");
        }

        detailsList.innerHTML = "";

        if (window.location.pathname.includes("/qr") && inputVal) {
            appendDetailItem("fas fa-qrcode", `Scanned Payload: ${inputVal}`, false, "var(--primary-color)");
        }

        if (data.details && Array.isArray(data.details)) {
            data.details.forEach((detail) => {
                const iconClass = isSafe ? "fas fa-check" : "fas fa-exclamation-triangle";
                appendDetailItem(iconClass, String(detail), !isSafe);
            });
        }

        if (data.screenshot_url) {
            const linkHtml = `Live Preview: <a href="${data.screenshot_url}" target="_blank" onclick="event.stopPropagation();" style="color: #4facfe; text-decoration: underline; font-weight: bold; cursor: pointer;">View Live Screenshot</a>`;
            appendDetailItem("fas fa-camera", linkHtml, false, "var(--primary-color)");
        }

        resultsContainer.classList.remove("hidden");
    }
    
    async function performAnalysis(inputVal, endpoint, formKey) {
        try {
            const formData = new FormData();
            formData.append(formKey, inputVal);

            const response = await fetch(endpoint, {
                method: "POST",
                body: formData
            });

            const data = await response.json();
            renderResults(data, inputVal);
        } catch (error) {
            console.error("Error connecting to backend:", error);
            renderResults({
                is_safe: false,
                status: "Connection Error",
                details: ["Failed to connect to the analysis engine."]
            }, inputVal);
        } finally {
            setButtonLoading(false);
        }
    }

    function resolveEndpoint() {
        const path = window.location.pathname;

        if (path.includes("/ip")) return { endpoint: "/api/analyze/ip", formKey: "ip" };
        if (path.includes("/phone")) return { endpoint: "/api/analyze/phone", formKey: "phone" };
        if (path.includes("/url")) return { endpoint: "/api/analyze/url", formKey: "url" };
        if (path.includes("/sms")) return { endpoint: "/api/analyze/sms", formKey: "sms" };

        return { endpoint: "/api/analyze/email", formKey: "email" };
    }

    async function analyzeCurrentInput() {
        if (!targetInput || !analyzeBtn) return;

        const inputVal = targetInput.value.trim();
        if (!inputVal) return;

        setButtonLoading(true);
        const { endpoint, formKey } = resolveEndpoint();
        await performAnalysis(inputVal, endpoint, formKey);
    }

    if (analyzeBtn && !window.location.pathname.includes("/qr")) {
        analyzeBtn.addEventListener("click", analyzeCurrentInput);
    }

    if (targetInput && !window.location.pathname.includes("/sms") && !window.location.pathname.includes("/qr")) {
        targetInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                analyzeCurrentInput();
            }
        });
    }

    const qrReader = document.getElementById("reader");
    const startCamBtn = document.getElementById("start-camera-btn");
    const stopCamBtn = document.getElementById("stop-camera-btn");
    const qrUpload = document.getElementById("qr-upload");
    const qrDropZone = document.getElementById("qr-drop-zone");

    let html5QrCode;

    function routeScannedData(decodedText) {
        let targetApi = "";
        let formKey = "";
        let cleanData = decodedText;
        const textLower = decodedText.toLowerCase();

        const urlRegex = /^(https?:\/\/|[a-z0-9-]+\.[a-z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;

        if (textLower.startsWith("mailto:")) {
            cleanData = decodedText.substring(7);
            formKey = "email";
            targetApi = "/api/analyze/email";
        } else if (textLower.startsWith("tel:")) {
            cleanData = decodedText.substring(4);
            formKey = "phone";
            targetApi = "/api/analyze/phone";
        } else if (textLower.startsWith("sms:") || textLower.startsWith("smsto:")) {
            cleanData = decodedText.replace(/^(sms:|smsto:)/i, "");
            formKey = "sms";
            targetApi = "/api/analyze/sms";
        } else if (urlRegex.test(textLower)) {
            formKey = "url";
            targetApi = "/api/analyze/url";
        } else {
            renderResults({
                is_safe: false,
                status: "Unsupported QR Content",
                details: [
                    "The scanned QR code does not contain a supported vector.",
                    "We only analyze QR codes that map to an Email, Phone Number, SMS, or URL."
                ]
            }, decodedText);
            return;
        }

        performAnalysis(cleanData, targetApi, formKey);
    }

    if (qrReader && typeof Html5Qrcode !== "undefined") {
        html5QrCode = new Html5Qrcode("reader");

        if (startCamBtn) {
            startCamBtn.addEventListener("click", () => {
                if (resultsContainer) resultsContainer.classList.add("hidden");

                html5QrCode.start(
                    { facingMode: "environment" },
                    { fps: 10, qrbox: { width: 250, height: 250 } },
                    (decodedText) => {
                        if (html5QrCode.isScanning) {
                            html5QrCode.stop().then(() => {
                                startCamBtn.style.display = "inline-flex";
                                if (stopCamBtn) stopCamBtn.style.display = "none";
                            }).catch((err) => console.log(err));
                        }
                        routeScannedData(decodedText);
                    },
                    () => {}
                ).then(() => {
                    startCamBtn.style.display = "none";
                    if (stopCamBtn) stopCamBtn.style.display = "inline-flex";
                }).catch((err) => {
                    renderResults({
                        is_safe: false,
                        status: "Camera Error",
                        details: ["Error accessing camera: " + err]
                    }, "System Camera");
                });
            });
        }

        if (stopCamBtn) {
            stopCamBtn.addEventListener("click", () => {
                if (html5QrCode.isScanning) {
                    html5QrCode.stop().then(() => {
                        if (startCamBtn) startCamBtn.style.display = "inline-flex";
                        stopCamBtn.style.display = "none";
                    }).catch((err) => console.log(err));
                }
            });
        }
    }

    async function uploadQrFile(file) {
        if (!file) return;
        if (resultsContainer) resultsContainer.classList.add("hidden");

        const formData = new FormData();
        formData.append("file", file);

        try {
            const response = await fetch("/api/analyze/qr_upload", {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (data.success && data.payload) {
                routeScannedData(data.payload);
            } else {
                renderResults(data, "Uploaded QR Image");
            }
        } catch (err) {
            console.error("Backend scan failed:", err);
            renderResults({
                is_safe: false,
                status: "Scan Failed",
                details: ["Error connecting to the backend QR scanning service."]
            }, "Uploaded QR Image");
        }
    }

    if (qrUpload) {
        qrUpload.addEventListener("change", async (event) => {
            if (!event.target.files || event.target.files.length === 0) return;
            await uploadQrFile(event.target.files[0]);
            event.target.value = "";
        });
    }

    if (qrDropZone && qrUpload) {
        qrDropZone.addEventListener("click", () => qrUpload.click());
        qrDropZone.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                qrUpload.click();
            }
        });

        ["dragenter", "dragover"].forEach((eventName) => {
            qrDropZone.addEventListener(eventName, (event) => {
                event.preventDefault();
                qrDropZone.classList.add("drag-over");
            });
        });

        ["dragleave", "drop"].forEach((eventName) => {
            qrDropZone.addEventListener(eventName, (event) => {
                event.preventDefault();
                qrDropZone.classList.remove("drag-over");
            });
        });

        qrDropZone.addEventListener("drop", async (event) => {
            const file = event.dataTransfer && event.dataTransfer.files ? event.dataTransfer.files[0] : null;
            await uploadQrFile(file);
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            if (resultsContainer) resultsContainer.classList.add("hidden");
            if (targetInput) targetInput.value = "";
        });
    }
});