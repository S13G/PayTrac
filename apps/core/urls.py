from django.urls import path

from apps.core.views import *

urlpatterns = [
    path('verify/email', VerifyEmailView.as_view(), name="verify_email"),
    path(
        'resend/email/verify/code/resend',
        ResendEmailVerificationCodeView.as_view(),
        name="resend_email_verification_code"
    ),
    path('login', LoginView.as_view(), name="user_log_in"),
    path('logout', LogoutView.as_view(), name="logout"),
    path('refresh/token', RefreshView.as_view(), name="refresh_token"),
    path('request/forgot-password/code', RequestForgotPasswordCodeView.as_view(),
         name="request_forgotten_password_code"),
    path('verify/forgot-password/code', VerifyForgotPasswordCodeView.as_view(),
         name="verify_forgot_password_code"),
    path('change/forgot-password/<str:token>', ChangeForgottenPasswordView.as_view(),
         name="change_forgot_password"),
    path('change/new-password', ChangePasswordView.as_view(), name="change_password"),
    path('create-account', RegistrationView.as_view(), name="create_account"),
    path('business_profile/details', RetrieveUpdateDeleteProfileView.as_view(),
         name="get_update_delete_suer_profile"),
    path("client-profile/<str:client_id>/", RetrieveUpdateDeleteClientProfileView.as_view(),
         name="get_update_delete_client_profile"),
    path("create/client-profile/", CreateClientProfileView.as_view(), name="create_client_profile"),
    path('business/clients/all/', RetrieveAllClientProfileView.as_view(), name="get_all_client_profile"),
]
