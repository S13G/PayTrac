import uuid

from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from apps.common.models import BaseModel
from apps.core.models import ClientProfile
from apps.invoice.managers import InvoiceManager

User = get_user_model()


# Create your models here.


class Invoice(BaseModel):
    invoice_number = models.CharField(max_length=255, null=True, unique=True)
    business_owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="business_invoices", null=True)
    client = models.ForeignKey(ClientProfile, on_delete=models.CASCADE, related_name="client_invoices", null=True)
    issued_on = models.DateTimeField(null=True)
    due_on = models.DateTimeField(null=True)
    comment = models.TextField(blank=True, null=True)
    is_paid = models.BooleanField(default=False)

    objects = InvoiceManager()

    @property
    def total_price(self):
        total = 0
        for item in self.invoice_items.all():
            total += item.price * item.quantity
        return total

    @property
    def total_quantity(self):
        total = 0
        for item in self.invoice_items.all():
            total += item.quantity
        return total

    @property
    def is_overdue(self):
        return self.due_on < timezone.now()

    def save(self, *args, **kwargs):
        if not self.invoice_number:
            self.invoice_number = uuid.uuid4().hex[:12].upper()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.invoice_number} => {self.client.full_name}"


class InvoiceItem(BaseModel):
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name="invoice_items", null=True)
    title = models.CharField(max_length=255, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    quantity = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.invoice.invoice_number} => {self.title}"
