from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django_countries.serializer_fields import CountryField
from rest_framework import serializers as sr

from apps.common.validators import validate_phone_number, validate_bvn

User = get_user_model()


class RegisterSerializer(sr.Serializer):
    full_name = sr.CharField(default="John Bull")
    email = sr.CharField()
    bvn = sr.CharField(max_length=11, validators=[validate_bvn])
    password = sr.CharField(write_only=True)

    @staticmethod
    def validate_email(value):
        try:
            validate_email(value)
        except sr.ValidationError:
            raise sr.ValidationError("Invalid email address.")
        return value


class VerifyEmailSerializer(sr.Serializer):
    email = sr.CharField()
    otp = sr.IntegerField()

    @staticmethod
    def validate_email(value):
        try:
            validate_email(value)
        except sr.ValidationError:
            raise sr.ValidationError("Invalid email address.")
        return value


class ResendEmailVerificationCodeSerializer(sr.Serializer):
    email = sr.CharField()

    @staticmethod
    def validate_email(value):
        try:
            validate_email(value)
        except sr.ValidationError:
            raise sr.ValidationError("Invalid email address.")
        return value


class BusinessUserSerializer(sr.Serializer):
    id = sr.UUIDField(read_only=True)
    full_name = sr.CharField()
    email = sr.EmailField(read_only=True)
    avatar = sr.ImageField()
    bvn = sr.CharField()
    email_verified = sr.BooleanField(read_only=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)

        for field_name, field_value in data.items():
            if field_value is None:
                data[field_name] = ""

        return data

    def update(self, instance, validated_data):
        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance


class ClientProfileSerializer(sr.Serializer):
    id = sr.UUIDField(read_only=True)
    full_name = sr.CharField()
    business_name = sr.CharField()
    avatar = sr.ImageField()
    email = sr.EmailField(read_only=True)
    phone_number = sr.CharField(validators=[validate_phone_number])
    billing_address = sr.CharField()
    country = CountryField(name_only=True)
    state = sr.CharField()
    zip_code = sr.CharField()
    is_verified = sr.BooleanField(read_only=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)

        for field_name, field_value in data.items():
            if field_value is None:
                data[field_name] = ""

        return data

    def update(self, instance, validated_data):
        print(validated_data)
        print(instance)
        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance


class LoginSerializer(sr.Serializer):
    email = sr.CharField()
    password = sr.CharField(write_only=True)

    @staticmethod
    def validate_email(value):
        try:
            validate_email(value)
        except sr.ValidationError:
            raise sr.ValidationError("Invalid email address.")
        return value


class ChangePasswordSerializer(sr.Serializer):
    password = sr.CharField(max_length=50, min_length=6, write_only=True)
    confirm_pass = sr.CharField(max_length=50, min_length=6, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm = attrs.get('confirm_pass')

        if confirm != password:
            raise sr.ValidationError({"confirm_pass": "Passwords do not match"})
        return attrs


class RegisterClientSerializer(sr.Serializer):
    full_name = sr.CharField()
    business_name = sr.CharField(allow_blank=True, allow_null=True, required=False)
    avatar = sr.ImageField(allow_null=True, allow_empty_file=True, required=False)
    email = sr.CharField()
    phone_number = sr.CharField()
    billing_address = sr.CharField(allow_null=True, allow_blank=True, required=False)
    country = CountryField(name_only=True)
    state = sr.CharField(allow_null=True, allow_blank=True, required=False)
    zip_code = sr.IntegerField(allow_null=True, required=False)
