from django.urls import path

from apps.invoice.views import *

urlpatterns = [
    path('create/invoice/<str:client_id>/', CreateInvoiceView.as_view(), name="create_invoice"),
    path('all/', RetrieveAllInvoicesView.as_view(), name="get_all_invoice"),
    path('<str:invoice_id>/', RetrieveUpdateDeleteInvoiceView.as_view(), name="get_update_delete_invoice"),
    path('paid/all/', RetrievePaidInvoicesView.as_view(), name="paid_invoice"),
    path('unpaid/all/', RetrieveUnpaidInvoicesView.as_view(), name="unpaid_invoice"),
]
