// static/js/firebase-auth.js

import {
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signInWithPopup,
    signOut,
    onAuthStateChanged,
    sendPasswordResetEmail
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

import { auth, googleProvider } from "./firebase-init.js";

document.addEventListener("DOMContentLoaded", () => {
    const AUTH_CACHE_KEY = "phishing_detection_auth_user";

    const body = document.body;

    const flipCard = document.getElementById("flip-auth-card");

    const showSignupBtn = document.getElementById("show-signup-btn");
    const showLoginBtn = document.getElementById("show-login-btn");

    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");

    const googleLoginBtns = document.querySelectorAll(".google-login-btn");

    const logoutBtn = document.getElementById("logout-btn");
    const forgotPasswordBtn = document.getElementById("forgot-password-btn");

    const guestBox = document.getElementById("guest-auth-box");
    const userBox = document.getElementById("user-auth-box");
    const userName = document.getElementById("auth-user-name");
    const userEmail = document.getElementById("auth-user-email");

    const loginMessage = document.getElementById("login-message");
    const registerMessage = document.getElementById("register-message");

    const togglePasswordBtns = document.querySelectorAll(".toggle-password");

    togglePasswordBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const input = document.getElementById(targetId);
            const icon = btn.querySelector("i");
            
            if (input.type === "password") {
                input.type = "text";
                icon.classList.remove("fa-eye");
                icon.classList.add("fa-eye-slash");
            } else {
                input.type = "password";
                icon.classList.remove("fa-eye-slash");
                icon.classList.add("fa-eye");
            }
        });
    });

    function showMessage(element, message, type = "error") {
        if (!element) return;

        element.textContent = message;
        element.className = `flip-auth-message ${type}`;
    }

    function clearMessages() {
        if (loginMessage) {
            loginMessage.textContent = "";
            loginMessage.className = "flip-auth-message";
        }

        if (registerMessage) {
            registerMessage.textContent = "";
            registerMessage.className = "flip-auth-message";
        }
    }

    function cleanFirebaseError(error) {
        const code = error?.code || "";

        if (
            code === "auth/invalid-credential" ||
            code === "auth/wrong-password" ||
            code === "auth/user-not-found" ||
            code === "auth/email-already-in-use"
        ) {
            return "Invalid email or password.";
        }
        if (code === "auth/too-many-requests") {
            return "Too many failed attempts. Please try again later.";
        }

        if (code === "auth/invalid-email") {
            return "Please enter a valid email address.";
        }

        if (code === "auth/weak-password") {
            return "Password is too weak. Use at least 6 characters.";
        }

        if (code === "auth/popup-closed-by-user") {
            return "Google sign-in was closed before completion.";
        }

        if (code === "auth/network-request-failed") {
            return "Network error. Check your internet connection.";
        }

        return "Authentication failed. Please try again.";
    }

    function setAuthReady() {
        if (!body) return;

        body.classList.remove("auth-booting");
        body.classList.add("auth-ready");
    }

    function showGuestState() {
        if (guestBox) guestBox.classList.remove("hidden");
        if (userBox) userBox.classList.add("hidden");

        if (userName) userName.textContent = "";
        if (userEmail) userEmail.textContent = "";

        setAuthReady();
    }

    function showUserState(userData) {
        if (guestBox) guestBox.classList.add("hidden");
        if (userBox) userBox.classList.remove("hidden");

        if (userName) {
            userName.textContent = userData.displayName || "Logged in user";
        }

        if (userEmail) {
            userEmail.textContent = userData.email || "";
        }

        setAuthReady();
    }

    function saveCachedUser(user) {
        if (!user) {
            localStorage.removeItem(AUTH_CACHE_KEY);
            return;
        }

        const safeUser = {
            displayName: user.displayName || "Logged in user",
            email: user.email || ""
        };

        localStorage.setItem(AUTH_CACHE_KEY, JSON.stringify(safeUser));
    }

    function loadCachedUser() {
        try {
            const cached = localStorage.getItem(AUTH_CACHE_KEY);
            if (!cached) return null;

            const userData = JSON.parse(cached);

            if (!userData || !userData.email) {
                return null;
            }

            return userData;
                } catch {
            localStorage.removeItem(AUTH_CACHE_KEY);
            return null;
        }
    }

    const cachedUser = loadCachedUser();

    if (cachedUser) {
        showUserState(cachedUser);
    } else {
        showGuestState();
    }

    if (showSignupBtn && flipCard) {
        showSignupBtn.addEventListener("click", () => {
            clearMessages();
            flipCard.classList.add("is-flipped");
        });
    }

    if (showLoginBtn && flipCard) {
        showLoginBtn.addEventListener("click", () => {
            clearMessages();
            flipCard.classList.remove("is-flipped");
        });
    }

    if (forgotPasswordBtn) {
        forgotPasswordBtn.addEventListener("click", async () => {
            const email = document.getElementById("login-email").value.trim();
            if (!email) {
                showMessage(loginMessage, "Please enter your email address first.", "error");
                return;
            }
            try {
                await sendPasswordResetEmail(auth, email);
                showMessage(loginMessage, "If the email is registered, a reset link has been sent.", "success");
            } catch (error) {
                showMessage(loginMessage, "If the email is registered, a reset link has been sent.", "success");
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            const email = document.getElementById("login-email").value.trim();
            const password = document.getElementById("login-password").value;

            try {
                const result = await signInWithEmailAndPassword(auth, email, password);
                saveCachedUser(result.user);
                showUserState(result.user);
                showMessage(loginMessage, "Logged in successfully.", "success");
                window.location.href = "/";
            } catch (error) {
                showMessage(loginMessage, cleanFirebaseError(error), "error");
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            const email = document.getElementById("register-email").value.trim();
            const password = document.getElementById("register-password").value;
            const confirmPassword = document.getElementById("register-confirm-password").value;

            if (password.length < 6) {
                showMessage(registerMessage, "Password must be at least 6 characters.", "error");
                return;
            }

            if (password !== confirmPassword) {
                showMessage(registerMessage, "Passwords do not match.", "error");
                return;
            }

            try {
                const result = await createUserWithEmailAndPassword(auth, email, password);
                saveCachedUser(result.user);
                showUserState(result.user);
                showMessage(registerMessage, "Account created successfully.", "success");
                window.location.href = "/";
            } catch (error) {
                showMessage(registerMessage, cleanFirebaseError(error), "error");
            }
        });
    }

    googleLoginBtns.forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                const result = await signInWithPopup(auth, googleProvider);
                saveCachedUser(result.user);
                showUserState(result.user);
                window.location.href = "/";
            } catch (error) {
                const visibleMessage = flipCard?.classList.contains("is-flipped")
                    ? registerMessage
                    : loginMessage;

                showMessage(visibleMessage, cleanFirebaseError(error), "error");
            }
        });
    });

    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            try {
                localStorage.removeItem(AUTH_CACHE_KEY);
                showGuestState();

                await signOut(auth);

                window.location.href = "/";
            } catch (error) {
                console.error("Logout failed:", error);
            }
        });
    }

    const registerPasswordInput = document.getElementById("register-password");
    const strengthMeter = document.getElementById("strength-meter");
    const strengthBar = strengthMeter?.querySelector(".strength-bar");
    const strengthText = strengthMeter?.querySelector(".strength-text");

    if (registerPasswordInput && strengthMeter) {registerPasswordInput.addEventListener("input", (e) => {
        const val = e.target.value;
        
        if (val.length === 0) {
            strengthMeter.classList.add("hidden");
            return;
        }
        
        strengthMeter.classList.remove("hidden");
        
        const hasLower = /[a-z]/.test(val);
        const hasUpper = /[A-Z]/.test(val);
        const hasNumber = /[0-9]/.test(val);
        const hasSpecial = /[^a-zA-Z0-9]/.test(val);
        const isLength12 = val.length >= 12; 
        const isLength6 = val.length >= 6;

        let strength = 1;

        if (isLength12 && hasLower && hasUpper && hasNumber && hasSpecial) {
            strength = 3;
        } else if (isLength6 && (hasLower || hasUpper) && (hasNumber || hasSpecial)) {
            strength = 2;
        }

        strengthBar.className = "strength-bar";
        strengthText.className = "strength-text";

        if (strength === 1) {
            strengthBar.classList.add("weak");
            strengthText.classList.add("weak");
            strengthText.textContent = "Weak";
        } else if (strength === 2) {
            strengthBar.classList.add("medium");
            strengthText.classList.add("medium");
            strengthText.textContent = "Medium";
        } else if (strength === 3) {
            strengthBar.classList.add("strong");
            strengthText.classList.add("strong");
            strengthText.textContent = "Strong";
        }
        });
    }
    onAuthStateChanged(auth, (user) => {
        if (user) {
            saveCachedUser(user);
            showUserState(user);
        } else {
            localStorage.removeItem(AUTH_CACHE_KEY);
            showGuestState();
        }
    });
});