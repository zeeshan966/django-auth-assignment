from django.urls import path
from . import views

urlpatterns = [
    path("", views.home_view, name="home"),
    path("signup/", views.signup_view, name="signup"),
    path("login/", views.login_view, name="login"),
    path("verify-otp/", views.verify_otp_view, name="verify_otp"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("logout/", views.logout_view, name="logout"),
    path("biometrics/register/options/", views.biometric_register_options, name="biometric_reg_options"),
    path("biometrics/register/verify/", views.biometric_register_verify, name="biometric_reg_verify"),
    path("biometrics/login/options/", views.biometric_login_options, name="biometric_login_options"),
    path("biometrics/login/verify/", views.biometric_login_verify, name="biometric_login_verify"),
]