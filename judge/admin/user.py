from typing import Any

from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.http import HttpRequest


class UserAdmin(BaseUserAdmin):
  def get_readonly_fields(self, request: HttpRequest, obj: Any | None = ...) -> list[str] | tuple[Any, ...]:
    fields = super().get_readonly_fields(request, obj)
    fields += ('last_login', 'date_joined')
    if not request.user.is_superadmin:
        fields += ('user_permissions', 'groups', 'is_superuser')
    return fields