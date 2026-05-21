// static/js/firebase-auth.js

import {
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signInWithPopup,
    signOut,
    onAuthStateChanged
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

    const guestBox = document.getElementById("guest-auth-box");
    const userBox = document.getElementById("user-auth-box");
    const userName = document.getElementById("auth-user-name");
    const userEmail = document.getElementById("auth-user-email");

    const loginMessage = document.getElementById("login-message");
    const registerMessage = document.getElementById("register-message");

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

        if (code === "auth/email-already-in-use") {
            return "This email is already registered.";
        }

        if (code === "auth/invalid-email") {
            return "Please enter a valid email address.";
        }

        if (code === "auth/weak-password") {
            return "Password is too weak. Use at least 6 characters.";
        }

        if (
            code === "auth/invalid-credential" ||
            code === "auth/wrong-password" ||
            code === "auth/user-not-found"
        ) {
            return "Wrong email or password.";
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