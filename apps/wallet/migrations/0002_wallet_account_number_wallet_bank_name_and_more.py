# Generated by Django 4.2.5 on 2023-11-27 01:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='wallet',
            name='account_number',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='wallet',
            name='bank_name',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='wallet',
            name='flw_ref',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
