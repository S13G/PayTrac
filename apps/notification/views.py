from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.common.errors import ErrorCode
from apps.common.exceptions import RequestError
from apps.common.responses import CustomResponse
from apps.notification.models import Notification


# Create your views here.


class RetrieveAllNotificationsView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Retrieve all notifications",
        description=(
                "This endpoint allows an authenticated user to retrieve all notifications."
        ),
        tags=['Notification'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Successfully retrieved all notifications",
            ),
        }
    )
    def get(self, request):
        user = self.request.user
        notifications = user.user_notifications.values('id', 'title', 'body', 'created', 'is_read')
        return CustomResponse.success(message="Successfully retrieved all notifications", data=notifications)


class UpdateNotificationStatusView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Change notification read status",
        description="Update notification read status",
        tags=['Notification'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Success",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid notification id",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Notification does not exist",
            )
        }
    )
    def post(self, request, *args, **kwargs):
        user = self.request.user
        notification_id = self.kwargs.get("notification_id")
        if not notification_id:
            return RequestError(err_code=ErrorCode.INVALID_ENTRY, err_msg="Invalid notification id",
                                status_code=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.select_related('user').get(id=notification_id, user=user)
        except Notification.DoesNotExist:
            return RequestError(err_code=ErrorCode.NON_EXISTENT, err_msg="Notification does not exist",
                                status_code=status.HTTP_404_NOT_FOUND)

        notification.is_read = True
        notification.save()
        return CustomResponse.success(message="Success")
