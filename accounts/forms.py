from django import forms
from django.utils import timezone
from .models import User


class SignUpForm(forms.Form):
    email = forms.EmailField(required=False)
    phone = forms.CharField(max_length=15, required=False)
    surname = forms.CharField(max_length=100)
    dob = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if email:
            email = email.strip().lower()
            if User.objects.filter(email=email).exists():
                raise forms.ValidationError("An account with this email address already exists.")
        return email or None

    def clean_phone(self):
        phone = self.cleaned_data.get("phone")
        if phone:
            phone = phone.strip()
            if not phone.isdigit() or len(phone) < 10:
                raise forms.ValidationError("Enter a valid phone number with at least 10 digits.")
            if User.objects.filter(phone=phone).exists():
                raise forms.ValidationError("An account with this phone number already exists.")
        return phone or None

    def clean_dob(self):
        dob = self.cleaned_data.get("dob")
        if dob and dob >= timezone.now().date():
            raise forms.ValidationError("Date of birth must be in the past.")
        return dob

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        phone = cleaned_data.get("phone")
        if not email and not phone:
            raise forms.ValidationError("Enter at least one contact method: email address or phone number.")
        return cleaned_data


class OTPRequestForm(forms.Form):
    identifier = forms.CharField(
        max_length=255,
        label="Email or Phone",
        widget=forms.TextInput(attrs={"placeholder": "Enter email or phone number"}),
    )