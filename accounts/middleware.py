from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse


class SingleActiveDeviceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Admin panel ko single-device logout check se exempt rakho
            admin_prefix = reverse("admin:index")
            if request.path.startswith(admin_prefix):
                return self.get_response(request)

            session_token = request.session.get("device_session_token")
            db_token = (
                str(request.user.active_session_token)
                if getattr(request.user, "active_session_token", None)
                else None
            )

            login_url = reverse("login")
            exempt_paths = {login_url, reverse("signup"), reverse("verify_otp")}

            if request.path not in exempt_paths and session_token != db_token:
                logout(request)
                messages.warning(
                    request,
                    "Your account was accessed from another device. For your security, you have been signed out here."
                )
                return redirect(login_url)

        return self.get_response(request)