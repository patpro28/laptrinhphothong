import json
import os
from operator import attrgetter, itemgetter

import pyotp
import webauthn
from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db.models import Q
from django.forms import (BooleanField, CharField, ChoiceField, Form,
                          ModelForm, MultipleChoiceField,
                          inlineformset_factory)
from django.template.defaultfilters import filesizeformat
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _

from django_ace import AceWidget
from judge.models import Language, Organization, Problem, Profile, Submission
from judge.models.problem import LanguageLimit, Solution
from judge.models.problem_data import PublicSolution
from judge.utils.subscription import newsletter_id
from judge.widgets import (HeavyPreviewPageDownWidget, MartorWidget,
                           Select2MultipleWidget, Select2Widget)
from judge.widgets.select2 import (HeavySelect2MultipleWidget,
                                   SemanticCheckboxSelectMultiple,
                                   SemanticSelect, SemanticSelectMultiple)

TOTP_CODE_LENGTH = 6

two_factor_validators_by_length = {
    TOTP_CODE_LENGTH: {
        'regex_validator': RegexValidator(
            f'^[0-9]{{{TOTP_CODE_LENGTH}}}$',
            _(f'Two-factor authentication tokens must be {TOTP_CODE_LENGTH} decimal digits.'),
        ),
        'verify': lambda code, profile: not profile.check_totp_code(code),
        'err': _('Invalid two-factor authentication token.'),
    },
    16: {
        'regex_validator': RegexValidator('^[A-Z0-9]{16}$', _('Scratch codes must be 16 base32 characters.')),
        'verify': lambda code, profile: code not in json.loads(profile.scratch_codes),
        'err': _('Invalid scratch code.'),
    },
}


def fix_unicode(string, unsafe=tuple('\u202a\u202b\u202d\u202e')):
    return string + (sum(k in unsafe for k in string) - string.count('\u202c')) * '\u202c'


class CreateManyUserForm(Form):
    prefix_user = forms.CharField(label=_('prefix user'), max_length=10, required=True)
    start_id = forms.IntegerField(label=_('start id'), required=True)
    end_id = forms.IntegerField(label=_('end id'), required=True)
    organization = forms.ChoiceField(label=_('organization'), required=False, widget=forms.Select())
    info = forms.FileField(label=_('users information'), required=False)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fields['organization'].choices = [(item.id, item.name) for item in Organization.objects.all()]
    
    def clean_info(self):
        file = self.files.get('info', None)
        if file:
            ext = os.path.splitext(file.name)[1][1:]
            if ext.lower() != 'csv':
                raise forms.ValidationError(_('Wrong file type for information, expected "csv"'
                                              ', found %(ext)s')
                                            % {'ext': ext})

class ProfileForm(ModelForm):
    class Meta:
        model = Profile
        fields = ['about', 'timezone', 'language', 'ace_theme']
        widgets = {
            'timezone': Select2Widget(attrs={'style': 'width:100%'}),
            'language': Select2Widget(attrs={'style': 'width:100%'}),
            'ace_theme': Select2Widget(attrs={'style': 'width:100%'}),
        }

        if HeavyPreviewPageDownWidget is not None:
            widgets['about'] = HeavyPreviewPageDownWidget(
                preview=reverse_lazy('profile_preview'),
                attrs={'style': 'max-width:700px;min-width:700px;width:700px'},
            )

    def clean_about(self):
        if 'about' in self.changed_data and not self.instance.has_any_solves:
            raise ValidationError(_('You must solve at least one problem before you can update your profile.'))
        return self.cleaned_data['about']

    def clean(self):

        return self.cleaned_data

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)


class DownloadDataForm(Form):
    comment_download = BooleanField(required=False, label=_('Download comments?'))
    submission_download = BooleanField(required=False, label=_('Download submissions?'))
    submission_problem_glob = CharField(initial='*', label=_('Filter by problem code glob:'), max_length=100)
    submission_results = MultipleChoiceField(
        required=False,
        widget=Select2MultipleWidget(
            attrs={'style': 'width: 260px', 'data-placeholder': _('Leave empty to include all submissions')},
        ),
        choices=sorted(map(itemgetter(0, 0), Submission.RESULT)),
        label=_('Filter by result:'),
    )

    def clean(self):
        can_download = ('comment_download', 'submission_download')
        if not any(self.cleaned_data[v] for v in can_download):
            raise ValidationError(_('Please select at least one thing to download.'))
        return self.cleaned_data

    def clean_submission_problem_glob(self):
        if not self.cleaned_data['submission_download']:
            return '*'
        return self.cleaned_data['submission_problem_glob']

    def clean_submission_result(self):
        if not self.cleaned_data['submission_download']:
            return ()
        return self.cleaned_data['submission_result']


class ProblemSubmitForm(ModelForm):
    source = CharField(max_length=65536, required=False, widget=AceWidget(theme='twilight', no_ace_media=True))
    submission_file = forms.FileField(
        label=_('Source file'),
        required=False,
    )
    judge = ChoiceField(choices=(), widget=forms.HiddenInput(), required=False, label=_('Judge'))

    def clean(self):
        cleaned_data = super(ProblemSubmitForm, self).clean()
        self.check_submission()
        return cleaned_data

    def check_submission(self):
        source = self.cleaned_data.get('source', '')
        content = self.files.get('submission_file', None)
        language = self.cleaned_data.get('language', None)
        lang_obj = Language.objects.get(name=language)

        if (source != '' and content is not None) or (source == '' and content is None) or \
                (source != '' and lang_obj.file_only) or (content == '' and not lang_obj.file_only):
            raise forms.ValidationError(_('Source code/file is missing or redundant. Please try again'))

        if content:
            max_file_size = lang_obj.file_size_limit * 1024 * 1024
            ext = os.path.splitext(content.name)[1][1:]

            if ext.lower() != lang_obj.extension.lower():
                raise forms.ValidationError(_('Wrong file type for language %(lang)s, expected %(lang_ext)s'
                                              ', found %(ext)s')
                                            % {'lang': language, 'lang_ext': lang_obj.extension, 'ext': ext})

            elif content.size > max_file_size:
                raise forms.ValidationError(_('File size is too big! Maximum file size is %s')
                                            % filesizeformat(max_file_size))

    def __init__(self, *args, judge_choices=(), **kwargs):
        super(ProblemSubmitForm, self).__init__(*args, **kwargs)
        self.fields['language'].empty_label = None
        self.fields['language'].label_from_instance = attrgetter('display_name')
        self.fields['language'].queryset = Language.objects.filter(judges__online=True).distinct()

        if judge_choices:
            self.fields['judge'].widget = Select2Widget(
                attrs={'data-placeholder': _('Any judge')},
            )
            self.fields['judge'].choices = judge_choices

    class Meta:
        model = Submission
        fields = ['language']


class EditOrganizationForm(ModelForm):
    class Meta:
        model = Organization
        fields = ['about', 'logo_override_image', 'admins']
        widgets = {'admins': Select2MultipleWidget()}
        if HeavyPreviewPageDownWidget is not None:
            widgets['about'] = HeavyPreviewPageDownWidget(preview=reverse_lazy('organization_preview'))


class CustomAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(CustomAuthenticationForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'placeholder': _('Username')})
        self.fields['password'].widget.attrs.update({'placeholder': _('Password')})

        self.has_google_auth = self._has_social_auth('GOOGLE_OAUTH2')
        self.has_facebook_auth = self._has_social_auth('FACEBOOK')
        self.has_github_auth = self._has_social_auth('GITHUB_SECURE')

    def _has_social_auth(self, key):
        return (getattr(settings, 'SOCIAL_AUTH_%s_KEY' % key, None) and
                getattr(settings, 'SOCIAL_AUTH_%s_SECRET' % key, None))


class NoAutoCompleteCharField(forms.CharField):
    def widget_attrs(self, widget):
        attrs = super(NoAutoCompleteCharField, self).widget_attrs(widget)
        attrs['autocomplete'] = 'off'
        return attrs


class TOTPForm(Form):
    TOLERANCE = settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES

    totp_or_scratch_code = NoAutoCompleteCharField(required=False)

    def __init__(self, *args, **kwargs):
        self.profile = kwargs.pop('profile')
        super().__init__(*args, **kwargs)

    def clean(self):
        totp_or_scratch_code = self.cleaned_data.get('totp_or_scratch_code')
        try:
            validator = two_factor_validators_by_length[len(totp_or_scratch_code)]
        except KeyError:
            raise ValidationError(_('Invalid code length.'))
        validator['regex_validator'](totp_or_scratch_code)
        if validator['verify'](totp_or_scratch_code, self.profile):
            raise ValidationError(validator['err'])


class TOTPEnableForm(TOTPForm):
    def __init__(self, *args, **kwargs):
        self.totp_key = kwargs.pop('totp_key')
        super().__init__(*args, **kwargs)

    def clean(self):
        totp_validate = two_factor_validators_by_length[TOTP_CODE_LENGTH]
        code = self.cleaned_data.get('totp_or_scratch_code')
        totp_validate['regex_validator'](code)
        if not pyotp.TOTP(self.totp_key).verify(code, valid_window=settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES):
            raise ValidationError(totp_validate['err'])


class ProblemCloneForm(Form):
    code = CharField(max_length=20, validators=[RegexValidator('^[a-z0-9]+$', _('Problem code must be ^[a-z0-9]+$'))])

    def clean_code(self):
        code = self.cleaned_data['code']
        if Problem.objects.filter(code=code).exists():
            raise ValidationError(_('Problem with code already exists.'))
        return code


class LanguageLimitForm(ModelForm):
    class Meta:
        model = LanguageLimit
        fields = '__all__'


class SolutionForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['authors'].widget.can_add_related = False
        self.fields['authors'].queryset = Profile.objects.filter(
            Q(is_superuser=True) |
            Q(is_staff=True) |
            Q(user_permissions__codename='add_solution') |
            Q(user_permissions__codename='change_solution') |
            Q(user_permissions__codename='delete_solution')
        ).distinct()

    class Meta:
        model = Solution
        fields = '__all__'
        widgets = {
            'authors': SemanticSelectMultiple(),
            'content': MartorWidget(attrs={'data-markdownfy-url': reverse_lazy('problem_preview')}),
        }


LanguageInlineFormset = inlineformset_factory(
    Problem,
    LanguageLimit,
    form=LanguageLimitForm,
    extra=3,
    can_delete=True,
)


SolutionInlineFormset = inlineformset_factory(
    Problem,
    Solution,
    form=SolutionForm,
    extra=0,
    can_delete=True,
    max_num=1
)


class CreatePublicSolutionForm(ModelForm):
    class Meta:
        model = PublicSolution
        fields = ['description']