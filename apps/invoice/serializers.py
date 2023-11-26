from django.db import transaction
from rest_framework import serializers as sr

from apps.core.serializers import BusinessUserSerializer, ClientProfileSerializer
from apps.invoice.models import InvoiceItem


class InvoiceItemSerializer(sr.Serializer):
    id = sr.UUIDField(read_only=True)
    title = sr.CharField()
    price = sr.IntegerField()
    quantity = sr.IntegerField()


class InvoiceSerializer(sr.Serializer):
    id = sr.UUIDField(read_only=True)
    invoice_number = sr.CharField(read_only=True)
    business_owner = BusinessUserSerializer(read_only=True)
    client = ClientProfileSerializer(read_only=True)
    items = InvoiceItemSerializer(many=True, source="invoice_items", required=False)
    issued_on = sr.DateTimeField()
    due_on = sr.DateTimeField()
    comment = sr.CharField()
    total_price = sr.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total_quantity = sr.IntegerField(read_only=True)
    is_paid = sr.BooleanField(read_only=True)

    def update(self, instance, validated_data):
        # Extract invoice items data
        items_data = validated_data.pop("invoice_items", [])

        with transaction.atomic():
            # Update or create invoice items
            for item_data in items_data:
                item_title = item_data.get("title")

                # Filter the InvoiceItems based on title and invoice
                items_to_update = InvoiceItem.objects.filter(title=item_title, invoice=instance)

                # Update each matching InvoiceItem
                for item_to_update in items_to_update:
                    for key, value in item_data.items():
                        setattr(item_to_update, key, value)
                    item_to_update.save()

                # If no matching InvoiceItem is found, create a new one
                if not items_to_update.exists():
                    InvoiceItem.objects.create(title=item_title, invoice=instance, **item_data)

            # Update remaining fields of the invoice
            for key, value in validated_data.items():
                setattr(instance, key, value)

            instance.save()

        return instance
