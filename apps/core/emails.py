import pyotp
from django.http import Http404
from django.template.loader import render_to_string
from django.utils import timezone
from rest_framework.generics import get_object_or_404

from apps.core.models import OTPSecret
from utilities.emails import send_email


def send_otp_email(user, email=None, template=None):
    # Generate or retrieve the OTP secret for the user
    try:
        otp_secret = get_object_or_404(OTPSecret, user=user)
        otp_secret.created = timezone.now()
        otp_secret.save()
    except Http404:
        otp_secret = OTPSecret.objects.create(user=user, secret=pyotp.random_base32())

    # Generate the OTP using the secret
    totp = pyotp.TOTP(otp_secret.secret, interval=600)
    otp = totp.now()

    # Compose the email subject and content
    subject = 'One-Time Password (OTP) Verification'
    recipient = [user.email]
    context = {'full_name': user.full_name, 'otp': otp}
    message = render_to_string(template, context)

    # Send the email
    send_email(subject, recipient, message=message, template=template, context=context)


def send_invoice_email(user, email=None, template=None):
    # Compose the email subject and content
    subject = 'Invoice'
    recipient = [user.email]
    context = {'full_name': user.full_name, 'account_number': user.wallet.account_number,
               'bank_name': user.wallet.bank_name}
    message = render_to_string(template, context)

    # Send the email
    send_email(subject, recipient, message=message, template=template, context=context)
