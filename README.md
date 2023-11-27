# PayTrac - Small Business Payment Platform

![logo-icon.png](static%2Flogo-icon.png)

Streamline payment processes, manage client profiles, track transactions, and receive real-time alerts for unpaid
invoices with our Small Business Payment Platform - PayTrac.

## PayTrack API Link

https://pay-trac.vercel.app/

## Table of Contents

- [Introduction](#paytrac---small-business-payment-platform)
- [Key Features](#key-features)
- [Testing](#testing)
- [Additional Tips](#additional-tips)
- [Getting Started](#getting-started)

## Key Features

1. **Efficient Payment Processes:** Simplify payment workflows for small businesses, ensuring a smooth and hassle-free
   experience.
2. **Client Profile Management:** Provide business owners with a robust platform to manage and organize client profiles.
3. **Transaction Tracking:** Keep a close eye on transactions with our built-in tracking system.
4. **Real-Time Alerts:** Receive instant notifications for unpaid invoices.

## Testing

We've rigorously tested our platform to ensure that it meets the following objectives:

- Streamlined payment processes
- User-friendly client profile management
- Accurate transaction tracking
- Real-time alerts for unpaid invoices
- Chat Functionalities *(Coming soon)*

## Technologies used for API

- Python
- Django, Django Rest Framework
- SQLite3, PostgreSQL
- Docker and Docker-Compose
- Flutterwave
- Vercel for deployment
- Railway for database
- Cloudinary
- Gmail for free email

## Getting Started

Follow these steps to get the project up and running on your local machine:

1. Clone the repository:
    ```
    git clone https://github.com/PayTrac/PayTrac-API.git
   ```
2. Navigate to the project directory:
   ```
    cd PayTrac
   ```
3. Rename the ``.env.template`` to ``.env`` and update the values.


4. Build and run the service with
   ```
   docker-compose up --build
   ```
   or execute the command below in case permission is denied and root user/permission is needed
   ```
   sudo docker-compose up --build
   ```
   The service will build and run on port ``8000``


5. Launch a new terminal session and run the following commands(if you are not using docker, but for
   caution: `run them`)
   ```
   django mm
   ```
   The command above runs the migrations if there are some unapplied migrations
   ```
   django m
   ```
   The command above performs the database migrations


6. Create an admin user with the command below(make sure you fill in the admin details in the env):
   ```
   django createsu
   ```
   After creating the superuser, access the admin panel and login with your admin credentials with the
   link https://localhost:8000/admin/

   ### Admin Login Screen

   ![img1.png](static%2Fimg1.png)

   ### Admin Dashboard Screens (Has both Light and Dark Modes)

   ![img2.png](static%2Fimg2.png)


7. Add your data through the swagger doc and you can download the schema and import it into your postman collection
