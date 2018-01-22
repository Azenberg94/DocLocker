"""
Definition of forms.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.utils.translation import ugettext_lazy as _

class BootstrapAuthenticationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    username = forms.CharField(max_length=30,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))

class BootstrapSignupForm(UserCreationForm):
    """SignUp form which uses boostrap CSS."""
    username = forms.CharField(max_length=30,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))
    confirmPassword = forms.CharField(label=_("Password confirmation"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Repeat password'}))
    phoneNumber = forms.CharField(label=_("Phone Number"),
                               widget=forms.NumberInput({
                                   'class': 'form-control',
                                   'placeholder':'Ex : 0606060606'}))
    passphrase = forms.CharField(label=_("Secret passphrase"),
                                 max_length=255,
                                 widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder':'Ex: Once upon a time...'}))

class BootstrapValidationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    code = forms.CharField(label=_("Code"),
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder':'123456'}))
