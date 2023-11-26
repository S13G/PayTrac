from django.db import models


class InvoiceManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().select_related('client', 'business_owner')