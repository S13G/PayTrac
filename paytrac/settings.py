"""
Django settings for paytrac project.

Generated by 'django-admin startproject' using Django 4.2.7.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""
import os
from datetime import timedelta
from decouple import config
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition
DJANGO_APPS = [
    "jazzmin",  # not a django app but a custom django admin library
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

LOCAL_APPS = [
    'apps.core.apps.CoreConfig',
    'apps.common.apps.CommonConfig',
    'apps.invoice.apps.InvoiceConfig',
    'apps.notification.apps.NotificationConfig',
    'apps.social_auth.apps.SocialAuthConfig',
    'apps.wallet.apps.WalletConfig',
    'apps.chat.apps.ChatConfig',
]

THIRD_PARTY_APPS = [
    "cloudinary_storage",
    "debug_toolbar",
    "django_filters",
    "drf_spectacular",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
]

INSTALLED_APPS = DJANGO_APPS + LOCAL_APPS + THIRD_PARTY_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "COERCE_DECIMAL_TO_STRING": False,
    "DEFAULT_PAGINATION_CLASS": "apps.common.paginator.CustomPagination",
    # "EXCEPTION_HANDLER": "apps.common.exceptions.custom_exception_handler",
    "PAGE_SIZE": 30,
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "5000/day", "user": "10000/day"},
}

CORS_ALLOW_HEADERS = (
    "x-requested-with",
    "content-type",
    "accept",
    "origin",
    "authorization",
    "accept-encoding",
    "access-control-allow-origin",
    "content-disposition",
)

# CORS_ALLOWED_ORIGINS = config("CORS_ALLOWED_ORIGINS").split(" ")

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

SPECTACULAR_SETTINGS = {
    "TITLE": "PAYTRAC API",
    "DESCRIPTION": """""",
    "VERSION": "1.0.0",
    "CONTACT": "lookouttest91@zohomail.com",
    "SCHEMA_PATH_PREFIX": r'/api/v[0-9]',
    "SERVE_INCLUDE_SCHEMA": False,
    "DISABLE_ERRORS_AND_WARNINGS": True,
}

INTERNAL_IPS = [
    "127.0.0.1",
]

SIMPLE_JWT = {
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ACCESS_TOKEN_LIFETIME": timedelta(days=5),
}

ROOT_URLCONF = 'paytrac.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'paytrac.wsgi.application'

AUTH_USER_MODEL = "core.User"

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

STATICFILES_DIRS = [BASE_DIR / "static"]

STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles", "static")

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Email settings for SSL(Mainly for development and tests)
EMAIL_USE_TLS = False

EMAIL_USE_SSL = True

EMAIL_HOST = "smtp.gmail.com"

EMAIL_HOST_USER = config("EMAIL_HOST_USER")

EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")

EMAIL_PORT = 465

DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

JAZZMIN_SETTINGS = {
    "site_brand": "paytrac ADMIN",
    # title of the window (Will default to current_admin_site.site_title if absent or None)
    "site_title": "paytrac ADMIN",
    # Title on the login screen (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_header": "paytrac",
    # Logo to use for your site, must be present in static files, used for brand on top left
    "site_logo": "../static/svg.png",
    # Logo to use for your site, must be present in static files, used for login form logo (defaults to site_logo)
    "login_logo": "../static/svg.png",
    # CSS classes that are applied to the logo above
    "site_logo_classes": "img-circle",
    # Relative path to a favicon for your site, will default to site_logo if absent (ideally 32x32 px)
    "site_icon": "../static/svg.png",
    # Welcome text on the login screen
    "welcome_sign": "Welcome to the paytrac Admin Section",
    # Copyright on the footer
    "copyright": "paytrac Ltd 2023",
    # The model admin to search from the search bar, search bar omitted if excluded
    "search_model": [],
    # Field name on user model that contains avatar ImageField/URLField/Charfield or a callable that receives the user
    # "user_avatar": "avatar",

    ############
    # Top Menu #
    ############
    # Links to put along the top menu
    "topmenu_links": [
        # Url that gets reversed (Permissions can be added)
        {"name": "Home", "url": "admin:index", "permissions": ["auth.view_user"]},
        # model admin to link to (Permissions checked against model)
        {"model": "core.User"},
        # App with dropdown menu to all its models pages (Permissions checked against models)
        {"app": "core"},

    ],

    #############
    # User Menu #
    #############
    # Additional links to include in the user menu on the top right ("app" url type is not allowed)
    "usermenu_links": [{"name": "paytrac Platform"}, {"model": "auth.user"}],

    #############
    # Side Menu #
    #############
    # Whether to display the side menu
    "show_sidebar": True,
    # Whether to aut expand the menu
    "navigation_expanded": True,
    # Hide these apps when generating side menu e.g (auth)
    "hide_apps": {"authtoken": ['tokenproxy'], "token_blacklist": ["blacklistedtoken", "outstandingtoken"]},
    # List of apps (and/or models) to base side menu ordering off of (does not need to contain all apps/models)
    "order_with_respect_to": ["auth", "core", "core.user"],
    # Custom icons for side menu apps/models See https://fontawesome.com/icons?d=gallery&m=free&v=5.0.0,5.0.1,5.0.10,5.0.11,5.0.12,5.0.13,5.0.2,5.0.3,5.0.4,5.0.5,5.0.6,5.0.7,5.0.8,5.0.9,5.1.0,5.1.1,5.2.0,5.3.0,5.3.1,5.4.0,5.4.1,5.4.2,5.13.0,5.12.0,5.11.2,5.11.1,5.10.0,5.9.0,5.8.2,5.8.1,5.7.2,5.7.1,5.7.0,5.6.3,5.5.0,5.4.2
    # for the full list of 5.13.0 free icon classes
    "icons": {
        "core.group": "fas fa-users",
        "core.user": "fas fa-universal-access",
        "core.clientprofile": "far fa-user",
        "notification.notification": "fas fa-bell",
        "invoice.invoice": "fas fa-file-invoice",
        "wallet.wallet": "fas fa-wallet",
        "wallet.transaction": "fas fa-credit-card",
    },
    # Icons that are used when one is not manually specified
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",

    #############
    # UI Tweaks #
    #############
    # "show_ui_builder": True,
    "changeform_format": "horizontal_tabs",
    # override change forms on a per modeladmin basis
    "changeform_format_overrides": {
        "auth.user": "collapsible",
        "auth.group": "vertical_tabs",
    },
}

JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-info",
    "accent": "accent-navy",
    "navbar": "navbar-cyan navbar-dark",
    "no_navbar_border": False,
    "navbar_fixed": True,
    "layout_boxed": False,
    "footer_fixed": True,
    "sidebar_fixed": True,
    "sidebar": "sidebar-light-info",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "minty",
    "dark_mode_theme": "darkly",
    "button_classes": {
        "primary": "btn-outline-primary",
        "secondary": "btn-outline-secondary",
        "info": "btn-info",
        "warning": "btn-warning",
        "danger": "btn-danger",
        "success": "btn-outline-success"
    }
}

SILENCED_SYSTEM_CHECKS = [
    'staticfiles.W004',
]

# Flutterwave variables
FW_SECRET_KEY = config("FLUTTERWAVE_SECRET_KEY")

RAVE_SECRET_KEY = FW_SECRET_KEY

FW_PUBLIC_KEY = config("FLUTTERWAVE_PUBLIC_KEY")

RAVE_PUBLIC_KEY = FW_PUBLIC_KEY

FW_VERIFY_LINK = config("FW_VERIFY_LINK")

# database active connection minutes
CONN_MAX_AGE = 300
