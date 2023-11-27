from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group as DjangoGroup

from apps.core.models import *


class Group(DjangoGroup):
    class Meta:
        verbose_name = "group"
        verbose_name_plural = "groups"
        proxy = True


class GroupAdmin(BaseGroupAdmin):
    pass


class UserAdmin(BaseUserAdmin):
    list_display = (
        "full_name",
        "email",
        "email_verified",
        "bvn",
        "is_staff",
        "is_active",
        "provider",

    )
    list_display_links = (
        "full_name",
        "email",
    )
    list_filter = (
        "is_staff",
        "is_active",
    )
    list_per_page = 20
    fieldsets = (
        (
            "Login Credentials",
            {
                "fields": (
                    "email",
                    "password"
                )
            },
        ),
        (
            "Personal Information",
            {
                "fields": (
                    "full_name",
                    "avatar",
                    "bvn",
                )
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "provider",
                    "is_active",
                    "is_staff",
                    "email_verified",
                    "groups",
                    "user_permissions"
                )
            },
        ),
        (
            "Important Dates",
            {
                "fields": (
                    "created",
                    "updated",
                )
            },
        ),
    )

    add_fieldsets = (
        (
            "Personal Information",
            {
                "classes": ("wide",),
                "fields": (
                    "full_name",
                    "email",
                    "avatar",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )
    readonly_fields = ("created", "updated",)
    search_fields = ("email", "full_name",)
    ordering = ("email", "full_name",)


@admin.register(ClientProfile)
class ClientProfileAdmin(admin.ModelAdmin):
    fieldsets = [
        (
            'Profile Information', {
                'fields': [
                    "business_profile",
                    'full_name',
                    'business_name',
                    'avatar',
                    'email',
                    'phone_number',
                    'billing_address',
                    'country',
                    'state',
                    'zip_code',
                    'is_verified',
                ],
            }
        ),
    ]
    list_display = (
        'full_name',
        "phone_number",
        "email",
        "country",
        'created',
        'updated',
    )
    list_per_page = 20
    list_filter = (
        'is_verified',
    )
    search_fields = (
        "full_name",
        "phone_number",
        'email',
        'country',
        'state',
        'zip_code',
        'billing_address',
        'business_name',
    )


admin.site.register(User, UserAdmin)
admin.site.register(Group, GroupAdmin)
admin.site.unregister(DjangoGroup)
