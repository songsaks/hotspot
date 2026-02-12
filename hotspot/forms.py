from django import forms
from .models import Radcheck

class HotspotUserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}), label='Password')
    
    class Meta:
        model = Radcheck
        fields = ['username', 'password']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}),
        }

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.attribute = 'Cleartext-Password'
        instance.op = ':='
        instance.value = self.cleaned_data['password']
        if commit:
            instance.save()
        return instance

class UserImportForm(forms.Form):
    excel_file = forms.FileField(label="Select Excel File", widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.xlsx, .xls'}))
    profile = forms.ChoiceField(label="Assign to Profile", widget=forms.Select(attrs={'class': 'form-select'}), required=False)

    def __init__(self, *args, **kwargs):
        profile_choices = kwargs.pop('profile_choices', [])
        super().__init__(*args, **kwargs)
        self.fields['profile'].choices = [('', '--- No Profile ---')] + profile_choices
