# Create your models here.

import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email=None, phone=None, surname="", dob=None, password=None, **extra_fields):
        if not email and not phone:
            raise ValueError("At least one contact method, email address or phone number, is required.")

        email = self.normalize_email(email) if email else None
        phone = phone.strip() if phone else None

        user = self.model(
            email=email,
            phone=phone,
            surname=surname.strip(),
            dob=dob,
            **extra_fields,
        )

        # Set an unusable password for passwordless OTP or biometric login.
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, phone=None, surname="Admin", dob=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if not password:
            raise ValueError("A password is required for a superuser.")

        return self.create_user(
            email=email,
            phone=phone,
            surname=surname,
            dob=dob,
            password=password,
            **extra_fields,
        )


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    surname = models.CharField(max_length=100)
    dob = models.DateField(null=True, blank=True)

    # Unique session token used to enforce a single active device.
    active_session_token = models.UUIDField(null=True, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    # Primary identifier for Django admin and internal compatibility.
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["surname"]

    def rotate_session_token(self):
        """Generate a new session token and invalidate the previous device session."""
        self.active_session_token = uuid.uuid4()
        self.save(update_fields=["active_session_token"])
        return self.active_session_token

    def __str__(self):
        return f"{self.surname} ({self.email or self.phone})"


class LoginOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="otps")
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        # 5 minutes (300 seconds) validity
        return (timezone.now() - self.created_at).total_seconds() > 300

    def __str__(self):
        return f"OTP for {self.user} - {self.code}"


class BiometricCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="biometrics")
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()
    sign_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Biometric ({self.credential_id[:12]}...) for {self.user}"
