from django.contrib import admin

# Register your models here.

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import BiometricCredential, LoginOTP, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        "id",
        "surname",
        "email",
        "phone",
        "dob",
        "active_session_token",
        "is_active",
        "is_staff",
        "created_at",
    )
    list_filter = ("is_active", "is_staff", "created_at")
    search_fields = ("surname", "email", "phone")
    ordering = ("created_at",)
    readonly_fields = ("active_session_token", "created_at", "last_login")

    fieldsets = (
        ("Identity & Profile", {
            "fields": ("surname", "email", "phone", "dob"),
        }),
        ("Active Device Session", {
            "fields": ("active_session_token",),
        }),
        ("Permissions & Status", {
            "fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions"),
        }),
        ("Important Dates", {
            "fields": ("last_login", "created_at"),
        }),
    )

    add_fieldsets = (
        ("Create User", {
            "classes": ("wide",),
            "fields": ("surname", "email", "phone", "dob", "password1", "password2", "is_active", "is_staff"),
        }),
    )


@admin.register(LoginOTP)
class LoginOTPAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "code",
        "is_used",
        "is_expired_status",
        "created_at",
    )
    list_filter = ("is_used", "created_at")
    search_fields = ("user__surname", "user__email", "user__phone", "code")
    ordering = ("created_at",)
    readonly_fields = ("created_at",)

    @admin.display(boolean=True, description="Expired?")
    def is_expired_status(self, obj):
        return obj.is_expired()


@admin.register(BiometricCredential)
class BiometricCredentialAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "short_credential_id",
        "sign_count",
        "created_at",
    )
    list_filter = ("created_at",)
    search_fields = ("user__surname", "user__email", "user__phone", "credential_id")
    ordering = ("id", "created_at")
    readonly_fields = ("created_at",)

    @admin.display(description="Credential ID")
    def short_credential_id(self, obj):
        if len(obj.credential_id) > 24:
            return f"{obj.credential_id[:12]}...{obj.credential_id[-10:]}"
        return obj.credential_id
