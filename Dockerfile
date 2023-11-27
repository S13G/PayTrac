FROM python:3.9-alpine

# Create a folder for the app
WORKDIR /paytrac

# Install PostgreSQL dependencies
# Install build dependencies
RUN apk add --no-cache postgresql-dev gcc musl-dev libffi-dev

# Create a group and add a user to the group
RUN addgroup systemUserGroup && adduser -D -G systemUserGroup developer

# Grant executable permission to the group for the workdir
RUN chmod g+s /paytrac

# Switch to the user
USER developer

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CLOUDINARY_CLOUD_NAME=${CLOUDINARY_CLOUD_NAME}
ENV CLOUDINARY_API_KEY=${CLOUDINARY_API_KEY}
ENV CLOUDINARY_API_SECRET=${CLOUDINARY_API_SECRET}
ENV SECRET_KEY=${SECRET_KEY}
ENV EMAIL_HOST_USER=${EMAIL_HOST_USER}
ENV EMAIL_HOST_PASSWORD=${EMAIL_HOST_PASSWORD}
ENV DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE}
ENV ADMIN_EMAIL=${ADMIN_EMAIL}
ENV ADMIN_PASSWORD=${ADMIN_EMAIL}
ENV FLUTTERWAVE_SECRET_KEY=${FLUTTERWAVE_SECRET_KEY}
ENV FLUTTERWAVE_PUBLIC_KEY=${FLUTTERWAVE_PUBLIC_KEY}
ENV DATABASE_URL=${DATABASE_URL}
ENV FW_VERIFY_LINK=${FW_VERIFY_LINK}
ENV VERIFY_HASH=${VERIFY_HASH}

# Copy the requirements.txt file into the workdir
COPY requirements.txt requirements.txt

# Install the dependencies
RUN pip3 install -r requirements.txt

# Copy the Django project into the image
COPY .. .

# collectstatic without interactive input, perform migrations and create a superuser automatically
CMD python3 manage.py migrate --settings=$DJANGO_SETTINGS_MODULE && \
    python3 manage.py createsu --settings=$DJANGO_SETTINGS_MODULE && \
    python3 manage.py runserver 0.0.0.0:8000