import requests
from django.conf import settings
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.common.errors import ErrorCode
from apps.common.exceptions import RequestError
from apps.common.responses import CustomResponse

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
