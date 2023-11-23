from rest_framework.permissions import BasePermission


class IsAuthenticatedUser(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.auth.get('is_agent') == False
        )


class IsAuthenticatedAgent(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.auth.get('is_agent') == True
        )
