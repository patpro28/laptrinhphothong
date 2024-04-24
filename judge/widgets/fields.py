from django import forms

class Select(forms.Select):
    template_name = "forms/widgets/select.html"


class NumberInput(forms.NumberInput):
    template_name: str = "forms/widgets/number.html"


class HiddenInput(forms.HiddenInput):
    template_name: str = "forms/widgets/hidden.html"


class CheckboxInput(forms.CheckboxInput):
    template_name: str = "forms/widgets/checkbox.html"