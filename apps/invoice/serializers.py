from rest_framework import serializers as sr

from apps.core.serializers import BusinessUserSerializer, ClientProfileSerializer


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
    items = InvoiceItemSerializer(many=True)
    issued_on = sr.DateTimeField()
    due_on = sr.DateTimeField()
    comment = sr.CharField()
    total_price = sr.DecimalField(read_only=True)
    total_quantity = sr.IntegerField(read_only=True)
    is_paid = sr.BooleanField(read_only=True)

    def update(self, instance, validated_data):
        print(validated_data)
        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()
        return instance
