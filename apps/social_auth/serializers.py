import secrets

from django.contrib.auth import get_user_model
from faker import Faker
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.core.serializers import BusinessUserSerializer
from apps.social_auth import google
# from apps.core.serializers import ProfileSerializer
from apps.social_auth.funcs import register_social_user

fake = Faker()

User = get_user_model()


class GoogleSocialAuthSerializer(serializers.Serializer):
    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        user_data = self._validate_google_auth_token(auth_token)
        email = user_data.get('email')
        name = user_data.get("name", fake.name())
        password = secrets.token_hex(8)

        try:
            user = self._get_existing_user(email)
        except User.DoesNotExist:
            user = register_social_user(email=email, full_name=name, password=password)
        return self._get_user_data(user)

    @staticmethod
    def _validate_google_auth_token(auth_token):
        user_data = google.Google.validate(auth_token)
        if 'sub' not in user_data:
            raise ValidationError("The token is invalid or expired, please login again.")

        if user_data['iss'] != 'https://accounts.google.com':
            raise ValidationError("Invalid Issuer. Google didn't issue this.")
        return user_data

    @staticmethod
    def _get_existing_user(email):
        user = User.objects.get(email=email)
        return user

    @staticmethod
    def _get_user_data(user):
        user = user
        profile_serializer = BusinessUserSerializer(user).data
        return {
            "tokens": user.tokens(),
            "data": {
                "user_id": user.id,
                "profile": profile_serializer,
            }
        }
