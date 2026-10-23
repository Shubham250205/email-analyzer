from django import forms
from .models import ContactMessage


class ContactMessageForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ["name", "email", "message"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Enter your name", "autocomplete": "name"}),
            "email": forms.EmailInput(attrs={"placeholder": "Enter your email", "autocomplete": "email"}),
            "message": forms.Textarea(attrs={"placeholder": "Enter your message", "rows": 5}),
        }
