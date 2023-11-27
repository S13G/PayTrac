from django.urls import path

from apps.wallet.views import *

urlpatterns = [
    path("transactions/", TrackingTransactionsView.as_view(), name="transactions"),
    path("transactions/<str:transaction_reference>/", TransactionDetailView.as_view(), name="transaction_detail"),
    path('flutterwave-webhook', webhook, name='flutterwave-webhook'),
]
