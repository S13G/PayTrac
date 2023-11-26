from django.urls import path
from apps.notification.views import *

urlpatterns = [
    path("all", RetrieveAllNotificationsView.as_view(), name="notifications"),
    path("update/<str:notification_id>/status/", UpdateNotificationStatusView.as_view(),
         name="update_notification_status"),
]
