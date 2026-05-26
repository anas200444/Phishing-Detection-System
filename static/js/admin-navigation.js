import { auth } from "./firebase-init.js";

import {
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

const ADMIN_EMAILS = ["ans0225971@ju.edu.jo"];

const ADMIN_ALLOWED_PATHS = ["/", "/dashboard"];
const ADMIN_BLOCKED_PATHS = ["/url", "/ip", "/phone", "/sms", "/email", "/qr", "/report", "/login"];

function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function isKnownAdminEmail(email) {
    return ADMIN_EMAILS.includes(normalizeEmail(email));
}

function getCachedUserEmail() {
    try {
        const cached = localStorage.getItem("phishing_detection_auth_user");
        const user = cached ? JSON.parse(cached) : null;
        return normalizeEmail(user?.email);
    } catch {
        localStorage.removeItem("phishing_detection_auth_user");
        return "";
    }
}

function applyAdminShell() {
    document.body.classList.remove("is-normal-user", "is-guest");
    document.body.classList.add("is-authenticated", "is-admin");
    document.documentElement.classList.add("cached-admin-shell");

    const normalDashboard = document.getElementById("normal-dashboard-view");
    const adminDashboard = document.getElementById("admin-dashboard-view");

    if (normalDashboard) normalDashboard.classList.add("hidden");
    if (adminDashboard) adminDashboard.classList.remove("hidden");
}

function applyNormalShell(isGuest = false) {
    document.body.classList.remove("is-admin");
    document.documentElement.classList.remove("cached-admin-shell");

    if (isGuest) {
        document.body.classList.remove("is-authenticated");
        document.body.classList.add("is-guest", "is-normal-user");
    } else {
        document.body.classList.remove("is-guest");
        document.body.classList.add("is-authenticated", "is-normal-user");
    }

    const normalDashboard = document.getElementById("normal-dashboard-view");
    const adminDashboard = document.getElementById("admin-dashboard-view");

    if (normalDashboard) normalDashboard.classList.remove("hidden");
    if (adminDashboard) adminDashboard.classList.add("hidden");
}

function finishRoleCheck() {
    document.body.classList.remove("role-checking");
    document.body.classList.add("role-ready");
    document.documentElement.classList.remove("role-checking-html");
}

function isAdminAllowedPath(pathname) {
    return ADMIN_ALLOWED_PATHS.includes(pathname);
}

function isAdminBlockedPath(pathname) {
    return ADMIN_BLOCKED_PATHS.some(path => pathname === path || pathname.startsWith(`${path}/`));
}

function redirectAdminIfNeeded() {
    const path = window.location.pathname;

    if (isAdminBlockedPath(path) || !isAdminAllowedPath(path)) {
        window.location.replace("/");
        return true;
    }

    return false;
}

async function syncBackendSession(user) {
    if (!user) return null;

    const idToken = await user.getIdToken();

    try {
        await fetch("/api/auth/session", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${idToken}`
            }
        });
    } catch (error) {
        console.error("Backend session sync failed:", error);
    }

    return idToken;
}

async function getUserRole(user) {
    const idToken = await syncBackendSession(user);

    try {
        const response = await fetch("/api/auth/role", {
            headers: {
                Authorization: `Bearer ${idToken}`
            }
        });

        if (!response.ok) {
            return {
                is_admin: isKnownAdminEmail(user.email),
                email: user.email || ""
            };
        }

        const data = await response.json();

        return {
            ...data,
            is_admin: Boolean(data.is_admin) || isKnownAdminEmail(user.email)
        };
    } catch {
        return {
            is_admin: isKnownAdminEmail(user.email),
            email: user.email || ""
        };
    }
}

(function preApplyCachedRole() {
    const cachedEmail = getCachedUserEmail();

    if (isKnownAdminEmail(cachedEmail)) {
        document.addEventListener("DOMContentLoaded", () => {
            applyAdminShell();
        });
    }
})();

document.addEventListener("DOMContentLoaded", () => {
    onAuthStateChanged(auth, async (user) => {
        document.body.classList.remove("is-admin", "is-normal-user", "is-guest", "is-authenticated");

        if (!user) {
            applyNormalShell(true);
            finishRoleCheck();
            return;
        }

        const cachedEmail = getCachedUserEmail();

        if (isKnownAdminEmail(cachedEmail) || isKnownAdminEmail(user.email)) {
            applyAdminShell();

            if (redirectAdminIfNeeded()) {
                return;
            }
        }

        const role = await getUserRole(user);

        if (role.is_admin) {
            applyAdminShell();

            if (redirectAdminIfNeeded()) {
                return;
            }

            finishRoleCheck();
            return;
        }

        applyNormalShell(false);

        if (window.location.pathname === "/login") {
            window.location.replace("/");
            return;
        }

        finishRoleCheck();
    });
});