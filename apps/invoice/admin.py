from django.contrib import admin

from apps.invoice.models import Invoice, InvoiceItem


# Register your models here.

class InvoiceItemInline(admin.TabularInline):
    model = InvoiceItem
    extra = 1
    min_num = 1


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    inlines = [InvoiceItemInline]
    fieldsets = [
        (
            "Invoice information", {
                "fields": [
                    "invoice_number",
                    "business_owner",
                    "client",
                    "issued_on",
                    "due_on",
                    "comment",
                    "is_paid",
                ]
            }
        ),
    ]
    list_display = [
        "invoice_number",
        "business_owner",
        "client",
        "issued_on",
        "due_on",
        "is_paid",
        "is_overdue",
        "total_price",
        "total_quantity"
    ]
    list_per_page = 20
    list_filter = [
        "is_paid",
        "issued_on",
        "due_on",
    ]
    readonly_fields = [
        "invoice_number",
    ]
    search_fields = [
        "invoice_number",
        "business_owner",
        "client",
        "comment",
    ]

    @admin.display(description="Total price")
    def total_price(self, obj):
        return obj.total_price

    @admin.display(description="Total quantity")
    def total_quantity(self, obj):
        return obj.total_quantity

    @admin.display(description="Business owner name")
    def business_owner(self, obj):
        return obj.business_owner.full_name

    @admin.display(description="Client name")
    def client(self, obj):
        return obj.client.full_name
