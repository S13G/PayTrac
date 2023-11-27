from django.urls import path

from apps.wallet.views import *

urlpatterns = [
    path("transactions/", TrackingTransactionsView.as_view(), name="transactions"),
]
