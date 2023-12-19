import json

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.common.errors import ErrorCode
from apps.common.exceptions import RequestError
from apps.common.responses import CustomResponse
from apps.core.models import ClientProfile
from apps.invoice.models import Invoice

User = get_user_model()

headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {settings.FW_SECRET_KEY}"
}


# Create your views here.

class TrackingTransactionsView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Track wallet transactions",
        description="This endpoint tracks the business owner wallet transactions",
        tags=['Wallet'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Retrieved all transactions successfully"
            )
        }
    )
    def get(self, request):
        user = request.user
        url = f"https://api.flutterwave.com/v3/transactions"
        wallet_created = user.wallet.created.strftime("%Y-%m-%d")
        business_owner_email = user.email

        data = {
            "from": wallet_created,
            "to": timezone.now().strftime("%Y-%m-%d"),
        }

        try:
            response = requests.get(url, headers=headers, params=data).json()
            response_page_data = response.get('meta').get('page_info')
            response_data = response.get('data')
        except Exception as e:
            raise RequestError(err_code=ErrorCode.FAILED, err_msg=str(e), status_code=status.HTTP_400_BAD_REQUEST)

        data = {
            "total_transactions": response_page_data.get('total'),
            "page_number": response_page_data.get('current_page'),
            "total_pages": response_page_data.get('total_pages'),
            "transactions": [
                {
                    "id": transaction['id'],
                    "invoice_number": transaction['meta'].get('invoice number', 'N/A'),
                    "transaction_reference": transaction['tx_ref'],
                    "status": transaction['status'],
                    "charged_amount": transaction['charged_amount'],
                    "app_fee": transaction['app_fee'],
                    "amount_settled": transaction['amount_settled'],
                    "currency": transaction['currency'],
                    "created_at": transaction['created_at'],
                    "payment_type": transaction['payment_type'],
                    "customer_email": transaction['customer']['email'],
                    "customer_name": transaction['customer']['name'],
                    "customer_bank_name": transaction['meta'].get('bankname', 'N/A'),
                }
                for transaction in response_data
            ]
        }
        return CustomResponse.success(message="Retrieved all transactions successfully", data=data)


class TransactionDetailView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Retrieve specific transaction",
        description="This endpoint allows a business owner to retrieve a specific transaction, you'll pass the `transaction reference` not `invoice number` as a path parameter",
        tags=['Wallet'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Retrieved successfully"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid or no transaction reference"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        transaction_reference = self.kwargs.get('transaction_reference')
        if not transaction_reference:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Invalid or no transaction reference",
                               status_code=status.HTTP_400_BAD_REQUEST)

        url = f"https://api.flutterwave.com/v3/transactions"

        data = {
            "tx_ref": transaction_reference
        }

        try:
            response = requests.get(url, headers=headers, params=data).json()
            response_data = response.get('data')
        except Exception as e:
            raise RequestError(err_code=ErrorCode.FAILED, err_msg=str(e), status_code=status.HTTP_400_BAD_REQUEST)

        data = {
            "transactions": [
                {
                    "id": transaction['id'],
                    "invoice_number": transaction['meta'].get('invoice number', 'N/A'),
                    "transaction_reference": transaction['tx_ref'],
                    "status": transaction['status'],
                    "charged_amount": transaction['charged_amount'],
                    "app_fee": transaction['app_fee'],
                    "amount_settled": transaction['amount_settled'],
                    "currency": transaction['currency'],
                    "created_at": transaction['created_at'],
                    "payment_type": transaction['payment_type'],
                    "customer_email": transaction['customer']['email'],
                    "customer_name": transaction['customer']['name'],
                    "customer_bank_name": transaction['meta'].get('bankname', 'N/A'),
                }
                for transaction in response_data
            ]
        }
        return CustomResponse.success(message="Retrieved successfully", data=data)


@extend_schema(
    summary="Webhook endpoint",
    description="This endpoint allows a business owner to receive webhook notifications",
    tags=['Wallet'],
    responses={
        status.HTTP_200_OK: OpenApiResponse(
            description="Webhook processed successfully"
        ),
        status.HTTP_401_UNAUTHORIZED: OpenApiResponse(
            description="Invalid signature"
        ),
        status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
            description="Failed to verify transaction"
        ),
        status.HTTP_404_NOT_FOUND: OpenApiResponse(
            description="User not found"
        )
    }
)
@require_POST
@csrf_exempt
def webhook(request):
    secret_hash = settings.VERIFY_HASH
    signature = request.headers.get("Verif-Hash")

    if signature is None or (signature != secret_hash):
        # This request isn't from Flutterwave; discard
        raise RequestError(err_code=ErrorCode.UNAUTHORIZED_USER, err_msg="Invalid signature",
                           status_code=status.HTTP_401_UNAUTHORIZED)

    payload = json.loads(request.body)

    # Extract relevant details from the payload (adjust these based on your actual payload structure)
    email = payload.get('data').get('customer').get('email')
    transaction_id = payload.get('data').get('id')
    transaction_status = payload.get('data').get('status')

    try:
        # Retrieve the user from the database
        ClientProfile.objects.get(email=email)
    except ClientProfile.DoesNotExist:
        raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Client not found",
                           status_code=status.HTTP_404_NOT_FOUND)

    # Verify the transaction
    verification_url = f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify"

    try:
        verification_response = requests.get(verification_url, headers=headers).json()
    except requests.RequestException as e:
        raise RequestError(err_code=ErrorCode.FAILED, err_msg="Failed to verify transaction, " + str(e),
                           status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Check if the transaction is successful
    if verification_response.get('status') == 'success':
        if transaction_status == "successful":
            # Update invoice paid status
            invoice_number = verification_response.get('data').get('meta').get('invoice number')

            try:
                invoice = Invoice.objects.get(invoice_number=invoice_number)
                invoice.is_paid = True
                invoice.save()

                # Update the wallet balance with the successful transaction amount
                user = invoice.business_owner
                user.wallet.balance += verification_response.get('data').get('amount')
                user.wallet.save()
            except Exception as e:
                raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg=f"Error: {e}",
                                   status_code=status.HTTP_400_BAD_REQUEST)

    return JsonResponse({"message": "Webhook processed successfully"})
