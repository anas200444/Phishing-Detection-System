import { auth, db } from "./firebase-init.js";

import {
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

import {
    addDoc,
    collection,
    serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-firestore.js";

const COLLECTIONS = {
    url: "reported_urls",
    ip: "reported_ips",
    phone: "reported_phone_numbers",
    sms: "reported_sms_content",
    email: "reported_emails"
};

const TYPE_LABELS = {
    url: "URL",
    ip: "IP Address",
    phone: "Phone Number",
    sms: "SMS Content",
    email: "Email"
};

const HELP_TEXT = {
    url: "Example URL: https://example.com/login",
    ip: "Example IP: 192.168.1.10 or 2001:db8::1",
    phone: "Use international format. Example: +962791234567",
    sms: "Enter the suspicious SMS message text.",
    email: "Example Email: user@example.com"
};

document.addEventListener("DOMContentLoaded", () => {
    const authRequiredBox = document.getElementById("report-auth-required");
    const formPanel = document.getElementById("report-form-panel");
    const form = document.getElementById("report-indicator-form");
    const typeInput = document.getElementById("indicator-type");
    const valueInput = document.getElementById("indicator-value");
    const helpText = document.getElementById("indicator-help-text");
    const messageBox = document.getElementById("report-message");
    const submitBtn = document.getElementById("report-submit-btn");

    let currentUser = null;

    function showMessage(message, type = "error") {
        if (!messageBox) return;
        messageBox.textContent = message;
        messageBox.className = `report-message ${type}`;
    }

    function clearMessage() {
        if (!messageBox) return;
        messageBox.textContent = "";
        messageBox.className = "report-message";
    }

    function normalizeIndicator(type, value) {
        const trimmed = value.trim();

        if (type === "url") {
            try {
                const url = new URL(trimmed);
                url.hash = "";
                return url.toString();
            } catch {
                return trimmed;
            }
        }

        if (type === "email") return trimmed.toLowerCase();
        if (type === "phone") return trimmed.replace(/[\s()-]/g, "");
        if (type === "ip") return trimmed.toLowerCase();

        return trimmed;
    }

    function isValidIPv4(value) {
        const parts = value.split(".");
        if (parts.length !== 4) return false;

        return parts.every(part => {
            if (!/^\d{1,3}$/.test(part)) return false;
            const number = Number(part);
            return number >= 0 && number <= 255;
        });
    }

    function isValidIPv6(value) {
        const ipv6Regex =
            /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6})|:(:[0-9a-fA-F]{1,4}){1,7}|::)$/;

        return ipv6Regex.test(value);
    }

    function validateIndicator(type, rawValue) {
        const value = rawValue.trim();

        if (!value) {
            return { valid: false, message: "Indicator value is required." };
        }

        if (type === "url") {
            try {
                const parsed = new URL(value);

                if (!["http:", "https:"].includes(parsed.protocol)) {
                    return { valid: false, message: "URL must start with http:// or https://." };
                }

                if (!parsed.hostname.includes(".")) {
                    return { valid: false, message: "URL must contain a valid domain name." };
                }

                if (/\s/.test(value)) {
                    return { valid: false, message: "URL must not contain spaces." };
                }

                return { valid: true };
            } catch {
                return {
                    valid: false,
                    message: "Enter a valid URL, for example: https://example.com/login"
                };
            }
        }

        if (type === "email") {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

            if (!emailRegex.test(value)) {
                return {
                    valid: false,
                    message: "Enter a valid email address, for example: user@example.com"
                };
            }

            return { valid: true };
        }

        if (type === "ip") {
            if (!isValidIPv4(value) && !isValidIPv6(value)) {
                return { valid: false, message: "Enter a valid IPv4 or IPv6 address." };
            }

            return { valid: true };
        }

        if (type === "phone") {
            const normalizedPhone = value.replace(/[\s()-]/g, "");
            const phoneRegex = /^\+[1-9]\d{7,14}$/;

            if (!phoneRegex.test(normalizedPhone)) {
                return {
                    valid: false,
                    message: "Enter a valid phone number in international format, for example: +962791234567"
                };
            }

            return { valid: true };
        }

        if (type === "sms") {
            if (value.length < 5) {
                return { valid: false, message: "SMS content must be at least 5 characters." };
            }

            if (value.length > 1000) {
                return { valid: false, message: "SMS content must not exceed 1000 characters." };
            }

            return { valid: true };
        }

        return { valid: false, message: "Invalid indicator type selected." };
    }

    function updateHelpText() {
        const selectedType = typeInput.value;
        helpText.textContent = HELP_TEXT[selectedType] || "";
        valueInput.value = "";
        clearMessage();
    }

    typeInput?.addEventListener("change", updateHelpText);

    onAuthStateChanged(auth, async (user) => {
        currentUser = user;

        if (user) {
            const idToken = await user.getIdToken();

            try {
                const roleResponse = await fetch("/api/auth/role", {
                    headers: {
                        Authorization: `Bearer ${idToken}`
                    }
                });

                const role = roleResponse.ok ? await roleResponse.json() : { is_admin: false };

                if (role.is_admin) {
                    window.location.href = "/";
                    return;
                }
            } catch {
                // If role check fails, keep normal report behavior.
            }

            authRequiredBox?.classList.add("hidden");
            formPanel?.classList.remove("hidden");
        } else {
            formPanel?.classList.add("hidden");
            authRequiredBox?.classList.remove("hidden");
        }
    });

    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage();

        if (!currentUser) {
            showMessage("You must be logged in to report an indicator.", "error");
            return;
        }

        const indicatorType = typeInput.value;
        const rawValue = valueInput.value;
        const validation = validateIndicator(indicatorType, rawValue);

        if (!validation.valid) {
            showMessage(validation.message, "error");
            return;
        }

        const normalizedValue = normalizeIndicator(indicatorType, rawValue);
        const collectionName = COLLECTIONS[indicatorType];

        if (!collectionName) {
            showMessage("Invalid indicator type selected.", "error");
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Submitting...`;

        try {
            await addDoc(collection(db, collectionName), {
                indicator_type: indicatorType,
                indicator_label: TYPE_LABELS[indicatorType],
                indicator_value: normalizedValue,
                original_value: rawValue.trim(),
                reported_by: currentUser.uid,
                reported_by_email: currentUser.email || null,
                source: "web_report_form",
                user_agent: navigator.userAgent,
                status: "pending_review",
                timestamp: serverTimestamp()
            });

            form.reset();
            updateHelpText();
            showMessage("Report submitted successfully.", "success");
        } catch (error) {
            console.error("Firestore report error:", error);
            showMessage("Failed to submit report. Please check Firestore rules.", "error");
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `<i class="fas fa-paper-plane"></i> Submit Report`;
        }
    });

    updateHelpText();
});