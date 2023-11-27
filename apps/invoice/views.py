from django.db import transaction
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.common.errors import ErrorCode
from apps.common.exceptions import RequestError
from apps.common.responses import CustomResponse
from apps.core.models import ClientProfile
from apps.invoice.emails import send_invoice_email
from apps.invoice.models import Invoice, InvoiceItem
from apps.invoice.serializers import InvoiceSerializer
from apps.notification.models import Notification


# Create your views here.


class RetrieveAllInvoicesView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = InvoiceSerializer

    @extend_schema(
        summary="Retrieve all invoices / Recent Activity",
        description=(
                "This endpoint allows an authenticated user to retrieve all invoices."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Successfully retrieved all invoices",
            )
        }
    )
    def get(self, request):
        user = self.request.user
        invoices = user.business_invoices.order_by("-created")
        serialized_data = self.serializer_class(invoices, many=True).data
        return CustomResponse.success(message="Successfully retrieved all invoices", data=serialized_data)


class RetrieveUpdateDeleteInvoiceView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = InvoiceSerializer

    @extend_schema(
        summary="Retrieve invoice",
        description=(
                "This endpoint allows an authenticated user to retrieve an invoice."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide an invoice id"
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Invoice not found"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        user = self.request.user
        invoice_id = self.kwargs.get("invoice_id")
        if not invoice_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Invoice id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)

        try:
            invoice = Invoice.objects.get(id=invoice_id, business_owner=user)
        except Invoice.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Invoice not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        serialized_data = self.serializer_class(invoice).data
        return CustomResponse.success(message="Successfully retrieved invoice", data=serialized_data)

    @extend_schema(
        summary="Update invoice",
        description=(
                "This endpoint allows an authenticated user to update an invoice."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Updated successfully"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide an invoice id"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Invoice not found"
            )
        }
    )
    def patch(self, request, *args, **kwargs):
        user = self.request.user
        invoice_id = self.kwargs.get("invoice_id")
        if not invoice_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Invoice id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)

        try:
            invoice = Invoice.objects.get(id=invoice_id, business_owner=user)
        except Invoice.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Invoice not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(invoice, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        serialized_data = self.serializer_class(invoice).data
        return CustomResponse.success(message="Updated successfully", data=serialized_data,
                                      status_code=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="Delete invoice",
        description=(
                "This endpoint allows an authenticated user to delete an invoice."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Deleted successfully"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Invoice not found"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide an invoice id"
            )
        }
    )
    def delete(self, request, *args, **kwargs):
        user = self.request.user
        invoice_id = self.kwargs.get("invoice_id")
        if not invoice_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Invoice id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)

        try:
            invoice = Invoice.objects.get(id=invoice_id, business_owner=user)
        except Invoice.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Invoice not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        invoice.delete()
        return CustomResponse.success(message="Deleted successfully")


class CreateInvoiceView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = InvoiceSerializer

    @extend_schema(
        summary="Create Invoice",
        description=(
                "This endpoint allows an authenticated business owner to create an invoice for a client"
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                description="Created successfully"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide client profile id"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Client profile not found"
            )
        }
    )
    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        user = self.request.user
        client_id = self.kwargs.get("client_id")
        if not client_id:
            raise RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Client profile id not provided",
                               status_code=status.HTTP_400_BAD_REQUEST)

        try:
            client = ClientProfile.objects.get(id=client_id, business_profile=user)
        except ClientProfile.DoesNotExist:
            raise RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Client profile not found",
                               status_code=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Extract the 'items' data from the validated_data
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        items_data = validated_data.pop('items', [])

        # Create the invoice
        invoice = Invoice.objects.create(business_owner=user, client=client, **validated_data)

        # Create associated items using bulk_create
        items_instances = [InvoiceItem(invoice=invoice, **item) for item in items_data]
        InvoiceItem.objects.bulk_create(items_instances)

        Notification.objects.create(title=f"You have created an invoice for {client.full_name}", user=user)

        serialized_data = self.serializer_class(invoice).data

        send_invoice_email(user=user, invoice=invoice, template="invoice.html")

        return CustomResponse.success(message="Created successfully", data=serialized_data,
                                      status_code=status.HTTP_201_CREATED)


class RetrievePaidInvoicesView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = InvoiceSerializer

    @extend_schema(
        summary="Retrieve paid invoices",
        description=(
                "This endpoint allows an authenticated user to retrieve all paid invoices."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Retrieved successfully",
            )
        }
    )
    def get(self, request):
        user = request.user
        invoices = Invoice.objects.filter(business_owner=user, is_paid=True).order_by("-created")
        serialized_data = self.serializer_class(invoices, many=True).data
        return CustomResponse.success(message="Retrieved successfully", data=serialized_data)


class RetrieveUnpaidInvoicesView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = InvoiceSerializer

    @extend_schema(
        summary="Retrieve unpaid invoices",
        description=(
                "This endpoint allows an authenticated user to retrieve all unpaid invoices."
        ),
        tags=['Invoice'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Retrieved successfully",
            )
        }
    )
    def get(self, request):
        user = request.user
        invoices = Invoice.objects.filter(business_owner=user, is_paid=False).order_by("-created")
        serialized_data = self.serializer_class(invoices, many=True).data
        return CustomResponse.success(message="Retrieved successfully", data=serialized_data)
