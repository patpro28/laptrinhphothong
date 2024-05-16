from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField, UsernameField
from django.forms import ModelForm
from django.urls import reverse, reverse_lazy
from django.utils.html import format_html
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from judge.models import Profile, User
from judge.utils.views import NoBatchDeleteMixin
from judge.views.register import CustomRegistrationForm
from judge.widgets import AdminMartorWidget


class ProfileForm(ModelForm):
    class Meta:
        widgets = {
            'about': AdminMartorWidget(attrs={'data-markdownfy-url': reverse_lazy('profile_preview')}),
        }


class TimezoneFilter(admin.SimpleListFilter):
    title = _('timezone')
    parameter_name = 'timezone'

    def lookups(self, request, model_admin):
        return Profile.objects.values_list('timezone', 'timezone').distinct().order_by('timezone')

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        return queryset.filter(timezone=self.value())


class ProfileAdmin(NoBatchDeleteMixin, admin.ModelAdmin):
    fieldsets = (
        (None, {
            "fields": (
                'user',
            ),
        }),
        (_('Information'), {
            "fields": (
                'display_rank', 'about', 
            ),
        }),
        (_('Settings'), {
            "fields": (
                'organizations', 'timezone', 'language', 'ace_theme', 'is_unlisted', 'mute'
            ),
        }),
        (_('Check'), {
            "fields": (
                'ip', 'notes', # 'current_contest'
            ),
        }),
    )
    readonly_fields = (
        'user',
        'ip',
    )
    list_display = ('user', 'fullname', 'timezone_full', 'last_access', 'ip', 'show_public')
    ordering = ('user',)
    search_fields = ('user__username', 'ip', 'user__email')
    list_filter = ('language', TimezoneFilter)
    actions = ('recalculate_points',)
    actions_on_top = True
    actions_on_bottom = True
    form = ProfileForm
    autocomplete_fields = ['organizations', 'language']
    # inlines = [WebAuthnInline]


    def get_fields(self, request, obj=None):
        return self.fields

    def get_readonly_fields(self, request, obj=None):
        fields = self.readonly_fields
        if not request.user.is_superadmin:
            fields += ('organizations',)
        return fields

    def show_public(self, obj):
        return format_html('<a href="{0}" class="view_on_site_button">{1}</a>',
                           obj.get_absolute_url(), gettext('View on site'))
    show_public.short_description = ''

    def fullname(self, obj):
        return obj.name
    fullname.admin_order_field = 'user__first_name'
    fullname.short_description = _('Full name')

    def timezone_full(self, obj):
        return obj.timezone
    timezone_full.admin_order_field = 'timezone'
    timezone_full.short_description = _('Timezone')

    def recalculate_points(self, request, queryset):
        count = 0
        for profile in queryset:
            profile.calculate_points()
            count += 1
        self.message_user(request, ngettext('%d user have scores recalculated.',
                                             '%d users have scores recalculated.',
                                             count) % count)
    recalculate_points.short_description = _('Recalculate scores')

