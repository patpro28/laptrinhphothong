from django.contrib import admin
from django.forms import ModelForm, ModelMultipleChoiceField
from django.utils.translation import gettext_lazy as _

from judge.models import Problem
from judge.widgets import AdminHeavySelect2MultipleWidget


class ProblemGroupAdmin(admin.ModelAdmin):
    fields = ('name', 'full_name')
    search_fields = ['name']

class ProblemTypeAdmin(admin.ModelAdmin):
    fields = ('name', 'full_name')
    search_fields = ['name']

class ProblemClassAdmin(admin.ModelAdmin):
    fields = ('name', 'full_name')
    search_fields = ['name']