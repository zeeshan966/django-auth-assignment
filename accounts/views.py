import base64
import json
import logging
import os
import random
import re
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from .forms import OTPRequestForm, SignUpForm
from .models import BiometricCredential, LoginOTP, User

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
_WEBAUTHN_SESSION_KEYS = (
    "pending_otp_user_id",
    "webauthn_reg_challenge",
    "webauthn_auth_challenge",
    "webauthn_auth_user_id",
)


def _generate_and_send_otp(user):
    """Mark previous unused OTPs as used and generate a new six-digit code."""
    LoginOTP.objects.filter(user=user, is_used=False).update(is_used=True)
    code = f"{random.SystemRandom().randint(0, 999999):06d}"
    otp_obj = LoginOTP.objects.create(user=user, code=code)
    print(f"[OTP DEBUG] 6-digit code for {user}: {code}")
    return otp_obj


def _complete_device_login(request, user):
    """Set a new session token and sign in while enforcing a single active device."""
    new_token = user.rotate_session_token()
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["device_session_token"] = str(new_token)


def _find_user_by_identifier(identifier: str):
    """Find a user by email address or phone number."""
    identifier = (identifier or "").strip()
    if not identifier:
        return None
    return (
        User.objects.filter(email__iexact=identifier).first()
        or User.objects.filter(phone=identifier).first()
    )


def _b64url_encode(raw_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def _b64url_decode_json(b64url_str: str) -> dict:
    if not isinstance(b64url_str, str) or not b64url_str:
        raise ValueError("Invalid base64url payload.")
    padding = "=" * ((4 - len(b64url_str) % 4) % 4)
    raw = base64.urlsafe_b64decode(b64url_str + padding).decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Decoded client data is not an object.")
    return parsed


def _resolve_rp_id(request) -> str:
    """Resolve a valid WebAuthn Relying Party ID matching the current host."""
    raw_host = (request.get_host() or "").split(":")[0].strip().strip("[]").lower()
    if raw_host in ("", "localhost", "127.0.0.1", "::1"):
        return "localhost"
    if _DOMAIN_RE.match(raw_host):
        return raw_host
    return "localhost"


def _expected_origin(request) -> str:
    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{request.get_host()}"


def _clear_auth_transient_session(request):
    for key in _WEBAUTHN_SESSION_KEYS:
        request.session.pop(key, None)


def home_view(request):
    """Handle the root URL ('/')."""
    if request.user.is_authenticated:
        return redirect("dashboard")
    return login_view(request)


def signup_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                email=form.cleaned_data["email"],
                phone=form.cleaned_data["phone"],
                surname=form.cleaned_data["surname"],
                dob=form.cleaned_data["dob"],
            )
            _generate_and_send_otp(user)
            request.session["pending_otp_user_id"] = user.id
            messages.success(request, "Your account has been created. A six-digit sign-in code is ready.")
            return redirect("verify_otp")
    else:
        form = SignUpForm()

    return render(request, "accounts/signup.html", {"form": form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = OTPRequestForm(request.POST)
        if form.is_valid():
            identifier = form.cleaned_data["identifier"].strip()
            user = _find_user_by_identifier(identifier)
            if not user:
                messages.error(request, "No account was found with that email address or phone number.")
            else:
                _generate_and_send_otp(user)
                request.session["pending_otp_user_id"] = user.id
                messages.success(request, "Your six-digit sign-in code is ready.")
                return redirect("verify_otp")
    else:
        form = OTPRequestForm()

    return render(request, "accounts/login.html", {"form": form})


def verify_otp_view(request):
    pending_user_id = request.session.get("pending_otp_user_id")
    if not pending_user_id:
        return redirect("login")

    user = get_object_or_404(User, id=pending_user_id)

    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        if not (code.isdigit() and len(code) == 6):
            messages.error(request, "Please enter a valid 6-digit numeric code.")
        else:
            otp_record = (
                LoginOTP.objects.filter(user=user, code=code, is_used=False)
                .order_by("-created_at")
                .first()
            )

            if not otp_record:
                messages.error(request, "That six-digit code is incorrect. Please try again.")
            elif otp_record.is_expired():
                messages.error(request, "This code has expired. Request a new code.")
            else:
                otp_record.is_used = True
                otp_record.save(update_fields=["is_used"])
                _clear_auth_transient_session(request)
                _complete_device_login(request, user)
                messages.success(request, f"Welcome back, {user.surname}! You are signed in on this device.")
                return redirect("dashboard")

    latest_otp = LoginOTP.objects.filter(user=user, is_used=False).order_by("-created_at").first()
    demo_code = latest_otp.code if (latest_otp and not latest_otp.is_expired()) else None

    return render(request, "accounts/verify_otp.html", {"user_obj": user, "demo_code": demo_code})


@login_required
def dashboard_view(request):
    return render(request, "accounts/dashboard.html", {"user_obj": request.user})


def logout_view(request):
    _clear_auth_transient_session(request)
    logout(request)
    messages.info(request, "You have been signed out.")
    return redirect("login")


@login_required
@require_POST
def biometric_register_options(request):
    challenge = _b64url_encode(os.urandom(32))
    request.session["webauthn_reg_challenge"] = challenge

    user_handle = _b64url_encode(str(request.user.id).encode("utf-8"))
    account_name = request.user.email or request.user.phone or str(request.user.id)
    existing_creds = list(BiometricCredential.objects.filter(user=request.user))

    return JsonResponse({
        "challenge": challenge,
        "rp": {
            "name": "SecureAuth Demo",
            "id": _resolve_rp_id(request),
        },
        "user": {
            "id": user_handle,
            "name": account_name,
            "displayName": request.user.surname or account_name,
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "required",
        },
        "excludeCredentials": [{"id": c.credential_id} for c in existing_creds],
        "timeout": 60000,
    })


@login_required
@require_POST
def biometric_register_verify(request):
    expected_challenge = request.session.pop("webauthn_reg_challenge", None)
    if not expected_challenge:
        return JsonResponse({"error": "The challenge has expired or is missing."}, status=400)

    try:
        payload = json.loads(request.body.decode("utf-8"))
        cred_id = payload.get("id")
        resp = payload.get("response") if isinstance(payload.get("response"), dict) else {}
        client_data_b64 = resp.get("clientDataJSON")
        attestation_b64 = resp.get("attestationObject")

        if not isinstance(cred_id, str) or not cred_id or not client_data_b64 or not attestation_b64:
            return JsonResponse({"error": "Incomplete credential data."}, status=400)

        client_data = _b64url_decode_json(client_data_b64)
        if client_data.get("type") != "webauthn.create":
            return JsonResponse({"error": "Invalid WebAuthn ceremony type."}, status=400)
        if client_data.get("challenge") != expected_challenge:
            return JsonResponse({"error": "Challenge mismatch."}, status=400)
        if client_data.get("origin") != _expected_origin(request):
            return JsonResponse({"error": "Origin mismatch."}, status=400)

        BiometricCredential.objects.update_or_create(
            credential_id=cred_id,
            defaults={
                "user": request.user,
                "public_key": attestation_b64,
            },
        )
        return JsonResponse({"ok": True})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return JsonResponse({"error": f"Invalid registration payload: {exc}"}, status=400)
    except Exception:
        logger.exception("Unexpected error during biometric registration verification")
        return JsonResponse({"error": "Unable to verify biometric registration."}, status=500)


@require_POST
def biometric_login_options(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    identifier = payload.get("identifier") if isinstance(payload, dict) else ""
    user = _find_user_by_identifier(identifier or "")
    if not user:
        return JsonResponse({"error": "Account not found."}, status=404)

    creds = list(BiometricCredential.objects.filter(user=user))
    if not creds:
        return JsonResponse(
            {"error": "No Face ID or biometric credential is registered for this account."},
            status=400,
        )

    challenge = _b64url_encode(os.urandom(32))
    request.session["webauthn_auth_challenge"] = challenge
    request.session["webauthn_auth_user_id"] = user.id

    return JsonResponse({
        "challenge": challenge,
        "allowCredentials": [{"id": c.credential_id} for c in creds],
        "timeout": 60000,
    })


@require_POST
def biometric_login_verify(request):
    expected_challenge = request.session.pop("webauthn_auth_challenge", None)
    user_id = request.session.pop("webauthn_auth_user_id", None)

    if not expected_challenge or not user_id:
        return JsonResponse({"error": "The authentication challenge has expired."}, status=400)

    user = get_object_or_404(User, id=user_id)

    try:
        payload = json.loads(request.body.decode("utf-8"))
        cred_id = payload.get("id")
        resp = payload.get("response") if isinstance(payload.get("response"), dict) else {}
        client_data_b64 = resp.get("clientDataJSON")
        signature_b64 = resp.get("signature")

        if not isinstance(cred_id, str) or not cred_id or not client_data_b64 or not signature_b64:
            return JsonResponse({"error": "Assertion data is missing."}, status=400)

        cred = BiometricCredential.objects.filter(user=user, credential_id=cred_id).first()
        if not cred:
            return JsonResponse({"error": "Registered credential not found."}, status=400)

        client_data = _b64url_decode_json(client_data_b64)
        if client_data.get("type") != "webauthn.get":
            return JsonResponse({"error": "Invalid WebAuthn ceremony type."}, status=400)
        if client_data.get("challenge") != expected_challenge:
            return JsonResponse({"error": "Challenge mismatch."}, status=400)
        if client_data.get("origin") != _expected_origin(request):
            return JsonResponse({"error": "Origin mismatch."}, status=400)

        cred.sign_count += 1
        cred.save(update_fields=["sign_count"])

        _clear_auth_transient_session(request)
        _complete_device_login(request, user)
        messages.success(request, f"Biometric sign-in successful. Welcome, {user.surname}!")
        return JsonResponse({"redirect_url": reverse("dashboard")})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return JsonResponse({"error": f"Invalid authentication payload: {exc}"}, status=400)
    except Exception:
        logger.exception("Unexpected error during biometric login verification")
        return JsonResponse({"error": "Unable to complete biometric sign-in."}, status=500)