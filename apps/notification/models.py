from django.contrib.auth import get_user_model
from django.db import models

from apps.common.models import BaseModel

User = get_user_model()


# Create your models here.

class Notification(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_notifications")
    title = models.CharField(max_length=255)
    body = models.TextField(blank=True, null=True, default="")
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.full_name} => {self.title}"
