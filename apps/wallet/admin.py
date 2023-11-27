from django.contrib import admin

from apps.wallet.models import Wallet, Transaction


# Register your models here.

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Wallet Information", {
                "fields": (
                    "business_owner",
                    "balance",
                )
            }
        ),
    )
    list_display = (
        "account_number",
        "bank_name",
        "order_ref",
        "business_owner",
        "balance",
    )
    list_per_page = 20
    list_filter = (
        "balance",
    )

    @admin.display(description="Business owner name")
    def business_owner(self, obj):
        return obj.business_owner.full_name


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Transaction Information", {
                "fields": (
                    "wallet",
                    "client",
                    "amount",
                    "transaction_type",
                )
            }
        ),
    )
    list_display = (
        "wallet",
        "client",
        "amount",
        "transaction_type",
    )
    list_filter = (
        "amount",
        "transaction_type",
    )
    list_per_page = 20

    @admin.display(description="Client name")
    def client(self, obj):
        return obj.client.full_name

    @admin.display(description="Wallet name")
    def wallet(self, obj):
        return f"{obj.wallet.business_owner.full_name}'s Wallet"
