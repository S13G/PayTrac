from uuid import uuid4

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField

from apps.common.models import BaseModel
from apps.common.validators import validate_phone_number, validate_bvn
from apps.core.managers import CustomUserManager, ClientManager


# Create your models here.


class User(AbstractBaseUser, BaseModel, PermissionsMixin):
    full_name = models.CharField(_("Full name"), max_length=150, null=True)
    email = models.EmailField(_("Email address"), unique=True)
    avatar = models.ImageField(upload_to="static/business_avatars", null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    bvn = models.CharField(max_length=11, null=True, validators=[validate_bvn])
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    provider = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]

    objects = CustomUserManager()

    def __str__(self):
        return self.full_name

    def profile_image(self):
        return self.avatar.url if self.avatar else ""


class OTPSecret(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="otp_secret", null=True)
    secret = models.CharField(max_length=255, null=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.full_name


class ClientProfile(BaseModel):
    business_profile = models.ForeignKey(User, on_delete=models.CASCADE, related_name="business_clients")
    full_name = models.CharField(_("Full name"), max_length=150, default='Doe John')
    business_name = models.CharField(max_length=255, null=True, blank=True)
    avatar = models.ImageField(upload_to="static/client_avatars", null=True, blank=True)
    email = models.CharField(max_length=255, null=True, unique=True)
    phone_number = models.CharField(validators=[validate_phone_number], max_length=255, null=True)
    billing_address = models.CharField(max_length=255, null=True, blank=True)
    country = CountryField(null=True)
    state = models.CharField(max_length=255, null=True, blank=True)
    zip_code = models.PositiveIntegerField(null=True, blank=True)
    is_verified = models.BooleanField(default=True)

    objects = ClientManager()

    def __str__(self):
        return f"{self.full_name}"
