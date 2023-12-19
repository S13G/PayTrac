import uuid
from datetime import timedelta

import pyotp
import requests
from django.conf import settings
from django.contrib.auth import authenticate
from django.db import transaction, IntegrityError
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rave_python import Rave
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenBlacklistSerializer, \
    TokenRefreshSerializer, TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenBlacklistView, TokenRefreshView

from apps.common.errors import ErrorCode
from apps.common.exceptions import RequestError
from apps.common.responses import CustomResponse
from apps.core.emails import send_otp_email
from apps.core.models import OTPSecret, ClientProfile
from apps.core.serializers import *
from apps.notification.models import Notification
from apps.wallet.models import Wallet
from utilities.encryption import decrypt_token_to_profile, encrypt_profile_to_token

User = get_user_model()

# Create your views here.

"""
AUTHENTICATION AND OTHER AUTHORIZATION OPTIONS 
"""


class RegistrationView(APIView):
    serializer_class = RegisterSerializer

    @extend_schema(
        summary="Register user account",
        description=(
                "This endpoint allows a user to register a business account. "
                "**Note:** If the user already has an existing profile, an error message will be displayed."
                "**Note: If the user wants to create another kind of account, send the same details including the same entered password details**"
        ),
        tags=['Registration'],
        responses={
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="You already have an existing account",
            ),
            status.HTTP_201_CREATED: OpenApiResponse(
                description="Registered successfully",
            )
        }
    )
    @transaction.atomic()
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        email = validated_data['email']

        rave = Rave(settings.RAVE_PUBLIC_KEY, settings.RAVE_SECRET_KEY, usingEnv=False)

        try:
            User.objects.get(email=email)
            raise RequestError(err_code=ErrorCode.ALREADY_EXISTS, err_msg="Account with this email already exists",
                               status_code=status.HTTP_409_CONFLICT)
        except User.DoesNotExist:
            pass

        try:
            user = User.objects.create_user(**validated_data)
            res = rave.VirtualAccount.create({
                "email": email,
                "is_permanent": True,
                "bvn": validated_data['bvn'],
                "tx_ref": f"{uuid.uuid4().hex[:10].upper()}",
                "firstname": validated_data['full_name'].split(" ")[0],
                "lastname": validated_data['full_name'].split(" ")[1],
                "narration": validated_data['full_name']
            })
            res_data = res.get('data')
            Wallet.objects.create(business_owner=user, account_number=res_data.get('accountnumber'),
                                  bank_name=res_data.get('bankname'), order_ref=res_data.get('orderRef'))
        except Exception as e:
            raise RequestError(err_code=ErrorCode.FAILED, err_msg=f"Account registration failed. {e}",
                               status_code=status.HTTP_400_BAD_REQUEST)

        return CustomResponse.success(message="Business account registered successfully",
                                      status_code=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    serializer_class = VerifyEmailSerializer

    @extend_schema(
        summary="Email verification",
        description=
        """
        This endpoint allows a registered user to verify their email address with an OTP.
        The request should include the following data:

        - `email_address`: The user's email address.
        - `otp`: The otp sent to the user's email address.
        """,
        tags=['Email Verification'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Email verification successful or already verified.",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="OTP Error"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="User with this email not found or otp not found for user"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        code = self.request.data.get('otp')

        try:
            user = User.objects.select_related('otp_secret').get(email=email)
        except User.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User with this email not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        if user.email_verified:
            raise RequestError(err_code=ErrorCode.VERIFIED_USER, err_msg="Email verified already",
                               status_code=status.HTTP_200_OK)
        try:
            if not code or not user.otp_secret:
                raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="No OTP found for this account",
                                   status_code=status.HTTP_404_NOT_FOUND)

            # Verify the OTP
            totp = pyotp.TOTP(user.otp_secret.secret, interval=600)
            if not totp.verify(code):
                raise RequestError(err_code=ErrorCode.INCORRECT_OTP, err_msg="Invalid OTP",
                                   status_code=status.HTTP_400_BAD_REQUEST)

            # Check if the OTP secret has expired (10 minutes interval)
            current_time = timezone.now()
            expiration_time = user.otp_secret.created + timedelta(minutes=10)
            if current_time > expiration_time:
                raise RequestError(err_code=ErrorCode.EXPIRED_OTP, err_msg="OTP has expired",
                                   status_code=status.HTTP_400_BAD_REQUEST)
        except OTPSecret.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="No OTP secret found for this account",
                               status_code=status.HTTP_404_NOT_FOUND)

        # OTP verification successful
        user.email_verified = True
        user.save()
        user.otp_secret.delete()

        return CustomResponse.success(message="Email verification successful.")


class ResendEmailVerificationCodeView(APIView):
    serializer_class = ResendEmailVerificationCodeSerializer

    @extend_schema(
        summary="Send / resend email verification code",
        description=
        """
        This endpoint allows a registered user to send or resend email verification code to their registered email address.
        The request should include the following data:

        - `email_address`: The user's email address.
        """,
        tags=['Email Verification'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Verification code sent successfully. Please check your mail. or Email verified already.",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="User with this email not found"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User with this email not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        if user.email_verified:
            raise RequestError(err_code=ErrorCode.VERIFIED_USER, err_msg="Email already verified",
                               status_code=status.HTTP_200_OK)

        send_otp_email(user, email, template="email_verification.html")
        return CustomResponse.success("Verification code sent successfully. Please check your mail")


class LoginView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Login",
        description="""
        This endpoint authenticates a registered and verified user and provides the necessary authentication tokens.
        """,
        request=LoginSerializer,
        tags=['Profile Authentication'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Logged in successfully",
                response=BusinessUserSerializer,
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Account not active or Invalid credentials",
            ),
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        email = validated_data["email"]
        password = validated_data["password"]

        user = authenticate(request, email=email, password=password)

        if not user:
            raise RequestError(err_code=ErrorCode.INVALID_CREDENTIALS, err_msg="Invalid credentials",
                               status_code=status.HTTP_400_BAD_REQUEST)

        if not user.email_verified:
            raise RequestError(err_code=ErrorCode.UNVERIFIED_USER, err_msg="Verify your email first",
                               status_code=status.HTTP_400_BAD_REQUEST)

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {settings.FW_SECRET_KEY}"
        }

        try:
            Wallet.objects.get(business_owner=user)
        except Wallet.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Wallet not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        order_ref = user.wallet.order_ref

        url = f"https://api.flutterwave.com/v3/virtual-account-numbers/{order_ref}"

        try:
            response = requests.get(url, headers=headers).json()
            response_data = response.get('data')
        except Exception as e:
            raise RequestError(err_code=ErrorCode.FAILED, err_msg=str(e), status_code=status.HTTP_400_BAD_REQUEST)

        if user.wallet.balance == response_data.get('amount'):
            pass
        else:
            user.wallet.balance = response_data.get('amount')
            user.wallet.save()

        token_response = super().post(request)
        tokens = token_response.data

        data = {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "email_verified": user.email_verified,
            "bvn": user.bvn,
            "avatar": user.profile_image(),
            "wallet_id": user.wallet.id,
            "wallet_balance": user.wallet.balance,
            "wallet_account_number": user.wallet.account_number,
            "wallet_bank_name": user.wallet.bank_name,
        }
        response_data = {"tokens": tokens, "profile_data": data}
        return CustomResponse.success(message="Logged in successfully", data=response_data)


class LogoutView(TokenBlacklistView):
    serializer_class = TokenBlacklistSerializer

    @extend_schema(
        summary="Logout",
        description=
        """
        This endpoint logs out an authenticated user by blacklisting their access token.
        The request should include the following data:

        - `refresh`: The refresh token used for authentication.
        """,
        tags=['Logout'],
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Token is blacklisted",
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Logged out successfully"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        try:
            serializer.is_valid(raise_exception=True)
            return CustomResponse.success(message="Logged out successfully.")
        except TokenError:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Token is blacklisted",
                               status_code=status.HTTP_400_BAD_REQUEST)


class RefreshView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer

    @extend_schema(
        summary="Refresh token",
        description=
        """
        This endpoint allows a user to refresh an expired access token.
        The request should include the following data:

        - `refresh`: The refresh token.
        """,
        tags=['Token'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Refreshed successfully",
            ),
        }

    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data['access']
        return CustomResponse.success(message="Refreshed successfully", data=access_token)


class RequestForgotPasswordCodeView(APIView):
    serializer_class = ResendEmailVerificationCodeSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Request new password code for forgot password",
        description=
        """
        This endpoint allows a user to request a verification code to reset their password if forgotten.
        The request should include the following data:

        - `email`: The user's email address.
        """,
        tags=['Password Change'],
        responses={
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Account not found"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Password code sent successfully"
            )
        }

    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = self.request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Account not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        send_otp_email(user, email, "forgot_password.html")
        return CustomResponse.success(message="Password code sent successfully")


class VerifyForgotPasswordCodeView(APIView):
    serializer_class = VerifyEmailSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Verify forgot password code for unauthenticated users",
        description=
        """
        This endpoint allows a user to verify the verification code they got to reset the password if forgotten.
        The user will be stored in the token which will be gotten to make sure it is the right user that is
        changing his/her password

        The request should include the following data:

        - `email`: The user's email
        - `otp`: The verification code sent to the user's email.
        """,
        tags=['Password Change'],
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="OTP error"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Account not found"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Otp verified successfully"
            )
        }

    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        email = self.request.data.get("email")
        code = self.request.data.get("otp")

        try:
            user = User.objects.select_related('otp_secret').get(email=email)
        except User.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User with this email not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        try:
            if not code or not user.otp_secret:
                raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="No OTP found for this account",
                                   status_code=status.HTTP_404_NOT_FOUND)

            # Verify the OTP
            totp = pyotp.TOTP(user.otp_secret.secret, interval=600)
            if not totp.verify(code):
                raise RequestError(err_code=ErrorCode.INCORRECT_OTP, err_msg="Invalid OTP",
                                   status_code=status.HTTP_400_BAD_REQUEST)

            # Check if the OTP secret has expired (10 minutes interval)
            current_time = timezone.now()
            expiration_time = user.otp_secret.created + timedelta(minutes=10)
            if current_time > expiration_time:
                raise RequestError(err_code=ErrorCode.EXPIRED_OTP, err_msg="OTP has expired",
                                   status_code=status.HTTP_400_BAD_REQUEST)

        except OTPSecret.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="No OTP secret found for this account",
                               status_code=status.HTTP_404_NOT_FOUND)

        token = encrypt_profile_to_token(user)  # Encrypt the user profile to a token.
        return CustomResponse.success(message="Otp verified successfully", data=token)


class ChangeForgottenPasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Change password for forgotten password",
        description=
        """
        This endpoint allows the unauthenticated user to change their password after requesting for a code.
        The request should include the following data:

        - `password`: The new password.
        - `confirm_password`: The new password again.
        """,
        tags=['Password Change'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Password updated successfully",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Token not provided"
            )
        }
    )
    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        token = self.kwargs.get('token')
        if token is None:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Token not provided",
                               status_code=status.HTTP_404_NOT_FOUND)

        user = decrypt_token_to_profile(token)
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
        user.set_password(password)
        user.save()

        return CustomResponse.success(message="Password updated successfully")


class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        summary="Change password for authenticated users",
        description=
        """
        This endpoint allows the authenticated user to change their password.
        The request should include the following data:

        - `password`: The new password.
        - `confirm_password`: The new password again.
        """,
        tags=['Password Change'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Password updated successfully",
            ),
        }
    )
    @transaction.atomic()
    def post(self, request):
        user = self.request.user
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
        user.set_password(password)
        user.save()

        return CustomResponse.success(message="Password updated successfully")


class RetrieveUpdateDeleteProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = BusinessUserSerializer

    @extend_schema(
        summary="Retrieve user profile",
        description=
        """
        This endpoint allows a user to retrieve his/her profile.
        """,
        tags=['Profile'],
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide a profile id"
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            )
        }
    )
    def get(self, request):
        user = self.request.user
        if not user:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User doesn't exist",
                               status_code=status.HTTP_404_NOT_FOUND)
        serialized_data = self.serializer_class(user, context={"request": request}).data
        return CustomResponse.success(message="Retrieved profile successfully", data=serialized_data)

    @extend_schema(
        summary="Update user profile",
        description=
        """
        This endpoint allows a user to update his/her user profile.
        """,
        tags=['Profile'],
        responses={
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Updated successfully"
            )
        }
    )
    @transaction.atomic()
    def patch(self, request):
        user = self.request.user
        if not user:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User doesn't exist",
                               status_code=status.HTTP_404_NOT_FOUND)

        update_profile = self.serializer_class(user, data=self.request.data, partial=True, context={"request": request})

        update_profile.is_valid(raise_exception=True)
        updated = self.serializer_class(update_profile.save()).data
        return CustomResponse.success(message="Updated profile successfully", data=updated,
                                      status_code=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="Delete user profile",
        description=
        """
        This endpoint allows a user to delete his/her profile.
        """,
        tags=['Profile'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Deleted successfully"
            )
        }
    )
    def delete(self, request):
        user = self.request.user
        if not user:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="User doesn't exist",
                               status_code=status.HTTP_404_NOT_FOUND)

        user.delete()
        return CustomResponse.success(message="Deleted successfully")


"""
CLIENT PROFILE
"""


class RetrieveUpdateDeleteClientProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ClientProfileSerializer

    @extend_schema(
        summary="Retrieve client profile",
        description=(
                "This endpoint allows a business owner to retrieve his/her client's profile."
        ),
        tags=['Client Profile'],
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide a client profile id"
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Client profile not found"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        client_id = self.kwargs.get('client_id')
        if not client_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Client profile id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)
        user = request.user

        try:
            client = ClientProfile.objects.get(id=client_id, business_profile=user)
        except ClientProfile.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Client profile not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        serialized_data = self.serializer_class(client).data
        return CustomResponse.success(message="Retrieved client profile successfully", data=serialized_data)

    @extend_schema(
        summary="Update client profile",
        description=(
                "This endpoint allows a business owner to update his/her client's profile."
        ),
        tags=['Client Profile'],
        responses={
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Updated successfully"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide a client profile id"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Client profile not found"
            )
        }
    )
    def patch(self, request, *args, **kwargs):
        client_id = self.kwargs.get('client_id')
        if not client_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Client profile id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)
        user = request.user

        try:
            client = ClientProfile.objects.get(id=client_id, business_profile=user)
        except ClientProfile.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Client profile not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        updated_profile = self.serializer_class(client, data=self.request.data, partial=True)
        updated_profile.is_valid(raise_exception=True)
        updated_profile.save()
        updated_serialized_data = self.serializer_class(client).data
        return CustomResponse.success(message="Updated client profile successfully", data=updated_serialized_data,
                                      status_code=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="Delete client profile",
        description=(
                "This endpoint allows a business owner to delete his/her client's profile."
        ),
        tags=['Client Profile'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Deleted successfully"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Client profile not found"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide a client profile id"
            )
        }
    )
    def delete(self, request, *args, **kwargs):
        client_id = self.kwargs.get('client_id')
        if not client_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Client profile id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)
        user = request.user

        try:
            client = ClientProfile.objects.get(id=client_id, business_profile=user)
        except ClientProfile.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Client profile not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        client.delete()
        return CustomResponse.success(message="Deleted client profile successfully")


class RetrieveAllClientProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ClientProfileSerializer

    @extend_schema(
        summary="Retrieve all client profiles",
        description=(
                "This endpoint allows a business owner to retrieve all his/her client's profiles."
        ),
        tags=['Client Profile'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            ),
        }
    )
    def get(self, request):
        user = request.user
        all_clients = user.business_clients.all()
        serialized_data = self.serializer_class(all_clients, many=True).data
        return CustomResponse.success(message="Retrieved all client profiles successfully", data=serialized_data)


class CreateClientProfileView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = RegisterClientSerializer

    @extend_schema(
        summary="Add client profile",
        description=(
                "This endpoint allows a business owner to add his/her client's profile."
        ),
        tags=['Client Profile'],
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                description="Created successfully"
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Client profile already exists for this business"
            )
        }
    )
    @transaction.atomic
    def post(self, request):
        user = request.user
        if not user:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Business account not found",
                               status_code=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            client_profile = ClientProfile.objects.create(business_profile=user, **serializer.validated_data)
            Notification.objects.create(title="You have created a client profile", user=user)
        except IntegrityError:
            raise RequestError(err_code=ErrorCode.ALREADY_EXISTS, err_msg="Client profile already exists",
                               status_code=status.HTTP_409_CONFLICT)

        serialized_data = ClientProfileSerializer(client_profile, context={"request": request}).data
        return CustomResponse.success(message="Created client profile successfully", data=serialized_data,
                                      status_code=status.HTTP_201_CREATED)
