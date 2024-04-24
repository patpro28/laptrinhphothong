# coding=utf-8
from audioop import reverse
import re

from django import forms
from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.password_validation import get_default_password_validators
from django.forms import ChoiceField, ModelChoiceField, ModelMultipleChoiceField
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils.translation import gettext, gettext_lazy as _
from django.contrib.auth.forms import UserCreationForm
from django.views.generic import CreateView
# from sortedm2m.forms import SortedMultipleChoiceField

from judge.models import Language, Organization, Profile, TIMEZONE
from judge.utils.recaptcha import ReCaptchaField, ReCaptchaWidget
from judge.utils.subscription import Subscription, newsletter_id
from judge.widgets import Select2MultipleWidget, Select2Widget

bad_mail_regex = list(map(re.compile, settings.BAD_MAIL_PROVIDER_REGEX))


class CustomRegistrationForm(forms.ModelForm):
    username = forms.RegexField(regex=r'^(?=.{6,30}$)(?![_.])(?!.*[_.]{2})[a-z0-9_]+(?<![_.])$', max_length=30, label=_('Username'),
                                error_messages={'invalid': _('A username must contain lower latinh letters, '
                                                             'numbers, min length = 6, max length = 30')})
    error_messages = {
        'password_mismatch': _('The two password fields didn’t match.'),
    }
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text=_("Enter the same password as before, for verification."),
    )
    language = ModelChoiceField(queryset=Language.objects.all(), label=_('Preferred language'), empty_label=None,
                                widget=Select2Widget(attrs={'style': 'width:100%'}))
    class Meta:
        model = Profile
        fields = ('username',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs['autofocus'] = True

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def _post_clean(self):
        super()._post_clean()
        # Validate the password after self.instance is updated with form data
        # by super().
        password = self.cleaned_data.get('password2')
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except forms.ValidationError as error:
                self.add_error('password2', error)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class RegistrationView(CreateView):
    title = _('Registration')
    form_class = CustomRegistrationForm
    template_name = 'registration/registration_form.html'

    def get_success_url(self, user=None):
        return reverse_lazy('auth_login')

    def get_context_data(self, **kwargs):
        if 'title' not in kwargs:
            kwargs['title'] = self.title
        tzmap = settings.TIMEZONE_MAP
        kwargs['TIMEZONE_MAP'] = tzmap or 'http://momentjs.com/static/img/world.png'
        kwargs['TIMEZONE_BG'] = settings.TIMEZONE_BG if tzmap else '#4E7CAD'
        kwargs['password_validators'] = get_default_password_validators()
        kwargs['tos_url'] = settings.TERMS_OF_SERVICE_URL
        return super(RegistrationView, self).get_context_data(**kwargs)

    def register(self, form):
        user = super(RegistrationView, self).register(form)
        user.is_active = True
        user.save()
        return user

    def get_initial(self, *args, **kwargs):
        initial = super(RegistrationView, self).get_initial(*args, **kwargs)
        initial['timezone'] = settings.DEFAULT_USER_TIME_ZONE
        return initial


# class ActivationView(OldActivationView):
#     title = _('Registration')
#     template_name = 'registration/activate.html'

#     def get_context_data(self, **kwargs):
#         if 'title' not in kwargs:
#             kwargs['title'] = self.title
#         return super(ActivationView, self).get_context_data(**kwargs)


def social_auth_error(request):
    return render(request, 'generic-message.html', {
        'title': gettext('Authentication failure'),
        'message': request.GET.get('message'),
    })
