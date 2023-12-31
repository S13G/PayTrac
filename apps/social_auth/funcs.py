from typing import Dict

from django.contrib.auth import authenticate, get_user_model

User = get_user_model()


# Register a user with social authentication
def register_social_user(email: str, full_name: str, password: str) -> Dict[str, str]:
    """
    Register a social user.

    Args:
        email: The email address of the user.
        full_name: The full name of the user.
        password: The password of the user.

    Returns:
        A dictionary containing the user's email, full name, phone number, and tokens.
    """
    user_data = {
        "full_name": full_name,
        "email": email,
        "password": password
    }
    user = User.objects.create_user(**user_data)
    user.email_verified = True
    user.provider = True
    user.save()

    authenticated_user = authenticate(email=email, password=password)
    return authenticated_user
