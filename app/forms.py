"""
Definition of forms.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.utils.translation import ugettext_lazy as _

class BootstrapAuthenticationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    username = forms.CharField(max_length=254,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))

class BootstrapSignupForm(UserCreationForm):
    """SignUp form which uses boostrap CSS."""
    username = forms.CharField(max_length=254,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))
    confirmPassword = forms.CharField(label=_("ConfirmPassword"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'retaper Password'}))
    phoneNumber = forms.CharField(label=_("Numero de téléphone"),
                               widget=forms.NumberInput({
                                   'class': 'form-control',
                                   'placeholder':'0606060606'}))

class BootstrapValidationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    code = forms.CharField(label=_("Code"),
                               widget=forms.NumberInput({
                                   'class': 'form-control',
                                   'placeholder':'123456'}))
