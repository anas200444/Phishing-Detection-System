document.addEventListener("DOMContentLoaded", () => {
    const themeToggle = document.getElementById("theme-toggle");
    const body = document.body;
    const themeIcon = themeToggle.querySelector("i");

    if(themeToggle) {
        themeToggle.addEventListener("click", () => {
            body.classList.toggle("dark-mode");
            if (body.classList.contains("dark-mode")) {
                themeIcon.classList.replace("fa-moon", "fa-sun");
            } else {
                themeIcon.classList.replace("fa-sun", "fa-moon");
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

    function renderResults(data, inputVal) {
        if (data.is_safe) {
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

        statusBadge.textContent = data.status;

        if (confidenceText) {
            if (data.confidence !== undefined) {
                confidenceText.textContent = `Confidence: ${data.confidence}`;
            } else {
                confidenceText.textContent = ""; 
            }
        }

        detailsList.innerHTML = "";
        
        if (window.location.pathname.includes('/qr') && inputVal) {
            const typeLi = document.createElement("li");
            typeLi.innerHTML = `<i class="fas fa-qrcode" style="color: var(--primary-color)"></i> Scanned Payload: ${inputVal} `;
            detailsList.appendChild(typeLi);
        }

        if (data.details && Array.isArray(data.details)) {
            data.details.forEach(detail => {
                const li = document.createElement("li");
                const iconClass = data.is_safe ? "fas fa-check" : "fas fa-exclamation-triangle";
                if (!data.is_safe) li.className = "danger-item";
                
                li.innerHTML = `<i class="${iconClass}"></i> ${detail}`;
                detailsList.appendChild(li);
            });
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
            if (analyzeBtn) analyzeBtn.textContent = "Analyze";
        }
    }

    if(analyzeBtn && !window.location.pathname.includes('/qr')) {
        analyzeBtn.addEventListener("click", async () => {
            const inputVal = targetInput.value.trim();
            if (!inputVal) return;

            analyzeBtn.textContent = "Analyzing...";
            
            const isIpPage = window.location.pathname.includes('/ip');
            const isPhonePage = window.location.pathname.includes('/phone');
            const isUrlPage = window.location.pathname.includes('/url');
            const isSmsPage = window.location.pathname.includes('/sms');
            
            let endpoint = "/api/analyze/email";
            let formKey = "email";

            if (isIpPage) {
                endpoint = "/api/analyze/ip";
                formKey = "ip";
            } else if (isPhonePage) {
                endpoint = "/api/analyze/phone";
                formKey = "phone";
            } else if (isUrlPage) {
                endpoint = "/api/analyze/url";
                formKey = "url";
            } else if (isSmsPage) {
                endpoint = "/api/analyze/sms";
                formKey = "sms";
            }

            await performAnalysis(inputVal, endpoint, formKey);
        });
    }
    
    const qrReader = document.getElementById("reader");
    const startCamBtn = document.getElementById("start-camera-btn");
    const stopCamBtn = document.getElementById("stop-camera-btn");
    const qrUpload = document.getElementById("qr-upload");

    let html5QrCode;

    
    function routeScannedData(decodedText) {
        let targetApi = "";
        let formKey = "";
        let cleanData = decodedText;
        let textLower = decodedText.toLowerCase();

        
        const urlRegex = /^(https?:\/\/|[a-z0-9\-]+\.[a-z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;

        if (textLower.startsWith("mailto:")) {
            cleanData = decodedText.substring(7);
            formKey = "email";
            targetApi = "/api/analyze/email";
        } else if (textLower.startsWith("tel:")) {
            cleanData = decodedText.substring(4);
            formKey = "phone";
            targetApi = "/api/analyze/phone";
        } else if (textLower.startsWith("sms:") || textLower.startsWith("smsto:")) {
            cleanData = decodedText.replace(/^(sms:|smsto:)/i, '');
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
                resultsContainer.classList.add("hidden");
                html5QrCode.start(
                    { facingMode: "environment" },
                    { fps: 10, qrbox: { width: 250, height: 250 } },
                    (decodedText) => {
                        if (html5QrCode.isScanning) {
                            html5QrCode.stop().then(() => {
                                startCamBtn.style.display = "inline-block";
                                stopCamBtn.style.display = "none";
                            }).catch(err => console.log(err));
                        }
                        routeScannedData(decodedText);
                    },
                    (errorMessage) => { } 
                ).then(() => {
                    startCamBtn.style.display = "none";
                    stopCamBtn.style.display = "inline-block";
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
                        startCamBtn.style.display = "inline-block";
                        stopCamBtn.style.display = "none";
                    }).catch(err => console.log(err));
                }
            });
        }
    }
    
    if (qrUpload) {
        qrUpload.addEventListener("change", async (e) => {
            if (e.target.files.length === 0) return;
            
            resultsContainer.classList.add("hidden");
            const file = e.target.files[0];

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
            } finally {
                e.target.value = ""; 
            }
        });
    }

    if(clearBtn) {
        clearBtn.addEventListener("click", () => {
            resultsContainer.classList.add("hidden");
            if (targetInput) targetInput.value = "";
        });
    }
});