from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView


# Create your views here.

class TrackingTransactionsView(APIView):
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Track wallet transactions",
        description="This endpoint tracks the business owner wallet transactions",
        tags=['Wallet'],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Retrieved all transactions successfully"
            )
        }
    )
    def get(self, request):
        return status.HTTP_200_OK
