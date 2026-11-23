const WEBAUTHN_TIMEOUT_MS = 60000;
const FETCH_TIMEOUT_MS = 15000;

let isBiometricBusy = false;

function getCookie(name) {
    if (!document.cookie) return null;
    const parts = document.cookie.split(";");
    for (const rawPart of parts) {
        const part = rawPart.trim();
        if (part.startsWith(name + "=")) {
            return decodeURIComponent(part.slice(name.length + 1));
        }
    }
    return null;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

function base64urlToBuffer(base64url) {
    if (typeof base64url !== "string" || !base64url.length) {
        throw new Error("Invalid base64url string");
    }
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function setStatus(message, isError = true) {
    const el = document.getElementById("biometric-status");
    if (!el) return;
    el.textContent = message;
    el.style.color = isError ? "#dc2626" : "#059669";
}

function setButtonsBusy(busy) {
    isBiometricBusy = busy;
    const ids = ["register-biometric-btn", "biometric-login-btn"];
    for (const id of ids) {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = busy;
    }
}

async function fetchJsonWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
        const response = await fetch(url, {
            ...options,
            credentials: "same-origin",
            signal: controller.signal,
        });

        let data = {};
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
            try {
                data = await response.json();
            } catch {
                data = {};
            }
        }

        if (!response.ok) {
            throw new Error(data.error || `Request failed (HTTP ${response.status})`);
        }
        return data;
    } catch (err) {
        if (err.name === "AbortError") {
            throw new Error("The server request timed out. Please try again.");
        }
        throw err;
    } finally {
        clearTimeout(timer);
    }
}

function isWebAuthnSupported() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
        setStatus("Biometrics and WebAuthn are not supported in this browser.");
        return false;
    }
    if (!window.isSecureContext) {
        setStatus("Biometrics require HTTPS or a localhost/127.0.0.1 context.");
        return false;
    }
    return true;
}

function formatFriendlyError(err) {
    if (!err) return "Unknown biometric error.";
    if (err.name === "NotAllowedError") {
        return "The biometric prompt was canceled or timed out.";
    }
    if (err.name === "InvalidStateError") {
        return "This biometric credential is already registered on this device.";
    }
    if (err.name === "NotSupportedError") {
        return "The requested biometric method is not supported on this device or authenticator.";
    }
    if (err.name === "SecurityError") {
        return "Domain or origin is not allowed for WebAuthn on this page.";
    }
    return err.message || "The biometric operation failed.";
}

function isSafeLocalPath(url) {
    return typeof url === "string" && url.startsWith("/") && !url.startsWith("//");
}

async function registerBiometric() {
    if (isBiometricBusy) return;
    if (!isWebAuthnSupported()) return;

    const csrftoken = getCookie("csrftoken");
    if (!csrftoken) {
        setStatus("The CSRF token is missing. Refresh the page and try again.");
        return;
    }

    setButtonsBusy(true);
    try {
        setStatus("Loading biometric registration options...", false);

        const options = await fetchJsonWithTimeout("/biometrics/register/options/", {
            method: "POST",
            headers: {
                "X-CSRFToken": csrftoken,
            },
        });

        if (!options || !options.challenge || !options.user || !options.user.id || !options.rp) {
            throw new Error("Invalid biometric registration options received from server.");
        }

        const publicKey = {
            challenge: base64urlToBuffer(options.challenge),
            rp: options.rp,
            user: {
                id: base64urlToBuffer(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            pubKeyCredParams: options.pubKeyCredParams,
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "required",
                ...(options.authenticatorSelection || {}),
            },
            excludeCredentials: Array.isArray(options.excludeCredentials)
                ? options.excludeCredentials.map((cred) => ({
                      type: "public-key",
                      id: base64urlToBuffer(cred.id),
                  }))
                : [],
            timeout: options.timeout || WEBAUTHN_TIMEOUT_MS,
            attestation: "none",
        };

        setStatus("Complete the Face ID, fingerprint, or Windows Hello prompt...", false);
        const credential = await navigator.credentials.create({ publicKey });
        if (!credential) {
            setStatus("Biometric registration was not completed.");
            return;
        }

        const payload = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            },
        };

        await fetchJsonWithTimeout("/biometrics/register/verify/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrftoken,
            },
            body: JSON.stringify(payload),
        });

        setStatus("Face ID or biometrics has been securely registered for this account.", false);
    } catch (err) {
        setStatus(formatFriendlyError(err), true);
    } finally {
        setButtonsBusy(false);
    }
}

async function loginWithBiometric() {
    if (isBiometricBusy) return;
    if (!isWebAuthnSupported()) return;

    const identifierInput = document.getElementById("id_identifier");
    const identifier = identifierInput ? identifierInput.value.trim() : "";
    if (!identifier) {
        setStatus("Enter the email address or phone number registered to your account first.");
        if (identifierInput) identifierInput.focus();
        return;
    }

    const csrftoken = getCookie("csrftoken");
    if (!csrftoken) {
        setStatus("The CSRF token is missing. Refresh the page and try again.");
        return;
    }

    setButtonsBusy(true);
    try {
        setStatus("Preparing the biometric challenge...", false);

        const options = await fetchJsonWithTimeout("/biometrics/login/options/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrftoken,
            },
            body: JSON.stringify({ identifier }),
        });

        if (!options || !options.challenge) {
            throw new Error("Invalid biometric login options received from server.");
        }

        const publicKey = {
            challenge: base64urlToBuffer(options.challenge),
            allowCredentials: Array.isArray(options.allowCredentials)
                ? options.allowCredentials.map((cred) => ({
                      type: "public-key",
                      id: base64urlToBuffer(cred.id),
                  }))
                : [],
            userVerification: "required",
            timeout: options.timeout || WEBAUTHN_TIMEOUT_MS,
        };

        setStatus("Verify your identity with biometrics...", false);
        const assertion = await navigator.credentials.get({ publicKey });
        if (!assertion) {
            setStatus("Biometric verification was canceled.");
            return;
        }

        const payload = {
            identifier,
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null,
            },
        };

        const result = await fetchJsonWithTimeout("/biometrics/login/verify/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrftoken,
            },
            body: JSON.stringify(payload),
        });

        if (isSafeLocalPath(result.redirect_url)) {
            window.location.assign(result.redirect_url);
        } else {
            window.location.assign("/dashboard/");
        }
    } catch (err) {
        setStatus(formatFriendlyError(err), true);
    } finally {
        setButtonsBusy(false);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const regBtn = document.getElementById("register-biometric-btn");
    if (regBtn) {
        regBtn.addEventListener("click", registerBiometric);
    }

    const loginBtn = document.getElementById("biometric-login-btn");
    if (loginBtn) {
        loginBtn.addEventListener("click", loginWithBiometric);
    }
});