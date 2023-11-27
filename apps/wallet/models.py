from django.contrib.auth import get_user_model
from django.db import models

from apps.common.models import BaseModel
from apps.core.models import ClientProfile
from apps.wallet.choices import TRANSACTION_CHOICES

User = get_user_model()


# Create your models here.

class Wallet(BaseModel):
    account_number = models.CharField(max_length=50, null=True)
    bank_name = models.CharField(max_length=255, null=True)
    order_ref = models.CharField(max_length=255, null=True)
    business_owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.business_owner.full_name}'s Wallet"


class Transaction(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.DO_NOTHING, related_name="transactions")
    client = models.ForeignKey(ClientProfile, on_delete=models.DO_NOTHING, related_name="transactions")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(choices=TRANSACTION_CHOICES, max_length=10)

    def __str__(self):
        return f"{self.client.full_name} - {self.amount} to {self.wallet.business_owner.full_name}'s Wallet"
