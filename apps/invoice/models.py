from django.contrib.auth import get_user_model
from django.db import models

from apps.common.models import BaseModel

User = get_user_model()

# Create your models here.


class Invoice(BaseModel):
    pass