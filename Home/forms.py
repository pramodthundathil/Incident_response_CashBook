from django.contrib.auth.models import User 
from django.contrib.auth.forms import UserCreationForm
from .models import Income, Expense
from django.forms import ModelForm, Textarea, TextInput


class UserAddForm(UserCreationForm):
    class Meta:
        model = User 
        fields = ["first_name","last_name","email","username","password1","password2"]

        widgets = {

        }


class IncomeForm(ModelForm):
    class Meta:
        model = Income
        fields = ["amount","description","source","date"]
        widgets = {
            "amount":TextInput(attrs={"type":"number","class":"form-control"}),
            "description":Textarea(attrs={"class":"form-control"}),
            "source":TextInput(attrs={"type":"text","class":"form-control"}),
            "date":TextInput(attrs={"type":"date","class":"form-control"})
        }

class ExpenceForm(ModelForm):
    class Meta:
        model = Expense
        fields = ["amount","description","category","date"]

        widgets = {
            "amount":TextInput(attrs={"type":"number","class":"form-control"}),
            "description":Textarea(attrs={"class":"form-control"}),
            "category":TextInput(attrs={"type":"text","class":"form-control"}),
            "date":TextInput(attrs={"type":"date","class":"form-control"})
        }


