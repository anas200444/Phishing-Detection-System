document.addEventListener("DOMContentLoaded", () => {
    const themeToggle = document.getElementById("theme-toggle");
    const body = document.body;
    const themeIcon = themeToggle.querySelector("i");

    themeToggle.addEventListener("click", () => {
        body.classList.toggle("dark-mode");
        if (body.classList.contains("dark-mode")) {
            themeIcon.classList.replace("fa-moon", "fa-sun");
        } else {
            themeIcon.classList.replace("fa-sun", "fa-moon");
        }
    });

    const analyzeBtn = document.getElementById("analyze-btn");
    const targetInput = document.getElementById("target-input");
    const resultsContainer = document.getElementById("results-container");
    const clearBtn = document.getElementById("clear-btn");
    
    const statusIconBox = document.getElementById("status-icon-box");
    const statusIcon = document.getElementById("status-icon");
    const statusBadge = document.getElementById("status-badge");
    const confidenceText = document.getElementById("confidence-text");
    const detailsList = document.getElementById("details-list");

    if(analyzeBtn) {
        analyzeBtn.addEventListener("click", async () => {
            const inputVal = targetInput.value.trim();
            if (!inputVal) return;

            analyzeBtn.textContent = "Analyzing...";
            
            const isIpPage = window.location.pathname.includes('/ip');
            const isPhonePage = window.location.pathname.includes('/phone');
            
            let endpoint = "/api/analyze/email";
            let formKey = "email";

            if (isIpPage) {
                endpoint = "/api/analyze/ip";
                formKey = "ip";
            } else if (isPhonePage) {
                endpoint = "/api/analyze/phone";
                formKey = "phone";
            }

            try {
                const formData = new FormData();
                formData.append(formKey, inputVal);

                const response = await fetch(endpoint, {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();

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

                // Only update confidence if the element exists on the page (prevents errors on email page)
                if (confidenceText) {
                    confidenceText.textContent = `Confidence: ${data.confidence}`;
                }

                detailsList.innerHTML = "";
                data.details.forEach(detail => {
                    const li = document.createElement("li");
                    const iconClass = data.is_safe ? "fas fa-check" : "fas fa-exclamation-triangle";
                    if (!data.is_safe) li.className = "danger-item";
                    
                    li.innerHTML = `<i class="${iconClass}"></i> ${detail}`;
                    detailsList.appendChild(li);
                });

                resultsContainer.classList.remove("hidden");
            } catch (error) {
                console.error("Error connecting to backend:", error);
                alert("Failed to connect to the analysis engine.");
            } finally {
                analyzeBtn.textContent = "Analyze";
            }
        });
    }

    if(clearBtn) {
        clearBtn.addEventListener("click", () => {
            resultsContainer.classList.add("hidden");
            targetInput.value = "";
        });
    }
});