from .models import FullScan, User
from django.forms import ModelForm, TextInput, Textarea

from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy

class FullScanForm(ModelForm):
    class Meta:
        model = FullScan
        fields = ["domains"]
        widgets = {
            # "status": TextInput(attrs={
            #     'class':"form-control",
            #     'placeholder':"Введите статус"
            # }),
            "domains": Textarea(attrs={
                'class':"form-control",
                'placeholder':"Введите домены через enter"
            })
        }

class RegisterForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        fields = UserCreationForm.Meta.fields
