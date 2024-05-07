from typing import Any
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import random

from django.conf import settings
from django.core.files.storage import default_storage
from django.core.mail import send_mail
import json
from django.contrib.auth.models import User
from .models import Tenant, UserProfile
from django.core.exceptions import ObjectDoesNotExist
import string
from django.db import IntegrityError
from django.core.serializers import serialize
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile, User_Otp
from django.utils.html import strip_tags
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .serializers import User_OtpSerializer
import csv
from io import StringIO


def vaildate_email_address(email):
    """
    Validate the format of an email address.

    Args:
    - email (str): The email address to validate.

    Returns:
    - bool: True if the email address is valid, False otherwise.
    """
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False


def genrate_rendom_code(limit):
    """
    Generate a random code consisting of digits.

    Args:
    - limit (int): The length of the random code.

    Returns:
    - str: The generated random code.
    """
    return "".join(random.choices(string.digits, k=limit))


def create_tenant_response(email, useruuid_id):
    """
    Create a new tenant and generate a response containing relevant information.

    Args:
    - email (str): The email address associated with the tenant.
    - useruuid_id (str): The UUID of the user associated with the tenant.

    Returns:
    - Response: A JSON response containing information about the created tenant,
      including the tenant ID, serialized tenant data, and a success message.
      If an IntegrityError occurs (e.g., duplicate entry for email), returns
      a JSON response with an error message indicating the duplicate entry.
      If any other exception occurs, returns a JSON response with an error message.
    """
    try:
        new_tenant = Tenant.objects.create(
            name=f"{email}_tenant", useruuid_id=f"{useruuid_id}"
        )
        serialized_tenant = serialize("json", [new_tenant])
        tenant_id = new_tenant.id
        return Response(
            {
                "type": "success",
                "tenant_id": tenant_id,
                "serialized_tenant": json.loads(serialized_tenant),
                "message": "Tenant created successfully",
            },
            status=status.HTTP_201_CREATED,
        )

    except IntegrityError as e:
        return Response(
            {
                "type": "duplicate_error",
                "tenant_id": "",
                "serialized_tenant": "",
                "message": "Duplicate entry for email",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        return Response(
            {
                "type": "error",
                "tenant_id": "",
                "serialized_tenant": "",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


def retrive_user_details_from_database(email):
    """
    Retrieve user details from the database based on the email.

    Args:
    - email (str): The email address of the user.

    Returns:
    - dict or str: If the user profile exists, returns a dictionary containing the user profile data.
      If the user profile does not exist, returns the string "NOT FOUND".
    """
    try:
        user_profile = UserProfile.objects.get(email=email)
        return json.loads(user_profile)
    except ObjectDoesNotExist:
        return "nOT fOUND"


def genrate_otp_save_to_db(userMeta, message):
    """
    Generate OTP and save it to the database.

    Args:
    - userMeta (dict): User metadata containing OTP details.
    - message (str): Message associated with the OTP.

    Returns:
    - Response: A JSON response indicating the success or failure of OTP generation and saving to the database.
    """
    optserializer = User_OtpSerializer(data=userMeta)
    if optserializer.is_valid():
        instance = optserializer.save()
        serialized_data = optserializer.data
        return Response(
            {
                "type": "success",
                "data": serialized_data,
                "message": "Otp Genrated SucessFully",
            },
            status=status.HTTP_201_CREATED,
        )
    else:
        return Response(
            {
                "type": "error",
                "data": optserializer.errors,
                "message": "Something Was Wrong",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


def Send_email_via_template(subject, template_path, email):
    """
    Send an email using an HTML template.

    Args:
    - subject (str): The subject of the email.
    - template_path (str): The path to the HTML template file.
    - email (str or list): The recipient email address(es).

    Returns:
    - bool: True if the email was successfully sent, False otherwise.
    """
    try:
        plain_message = strip_tags(template_path)
        send_mail(
            subject,
            plain_message,
            settings.EMAIL_HOST_USER,
            email,
            html_message=template_path,
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def generate_tokens(user_id):
    """
    Generate access and refresh tokens for a user.

    Args:
    - user_id (int): The ID of the user for whom tokens are to be generated.

    Returns:
    - Response: A JSON response containing the generated access and refresh tokens,
      along with a success message. If the user does not exist, returns None.
    """
    try:
        user = User.objects.get(id=user_id)
        refresh_token = RefreshToken.for_user(user)
        access_token = AccessToken.for_user(user)
        tokens = {
            "access_token": str(refresh_token),
            "refresh_token": str(access_token),
        }
        return Response(
            {
                "type": "success",
                "tokens": tokens,
                "message": f"Auth Token and Refresh Token Genrated Successfully and OTP verification successful for User = {user}",
            },
            status=status.HTTP_200_OK,
        )
    except User.DoesNotExist:
        return None


def verifyOTP(otpCode):
    """
    Verify the provided OTP code.

    Args:
    - otpCode (str): The OTP code to be verified.

    Returns:
    - Response: A JSON response indicating the result of OTP verification.
      If the OTP is valid, updates the corresponding user's status to active
      and returns a success message along with OTP details and user UUID.
      If the OTP is invalid, returns an error message.
    """
    verify_otpRes: Any = User_Otp.objects.filter(otp=otpCode, is_active=True).first()
    if verify_otpRes:
        otp_data = serialize("json", [verify_otpRes])
        otp_json = json.loads(otp_data)
        useruuid = otp_json[0]["fields"]["useruuid"]
        User_Otp.objects.filter(pk=verify_otpRes.pk).update(is_active=False)
        user = User.objects.get(id=useruuid)
        user.is_active = True
        user.save()
        return Response(
            {
                "type": "success",
                "otp_json": otp_json,
                "useruuid": useruuid,
                "message": "OTP verification successful",
            },
            status=status.HTTP_200_OK,
        )
    else:
        return Response(
            {"type": "error", "otp_json": "", "useruuid": "", "message": "Invalid OTP"},
            status=status.HTTP_400_BAD_REQUEST,
        )


def get_file_contents(file_path):
    """
    Retrieve the contents of a file from storage.

    Args:
    - file_path (str): The path to the file.

    Returns:
    - str or None: The contents of the file as a string if the file exists,
      or None if the file is not found.
    """
    try:
        with default_storage.open(file_path, "r") as file:
            file_contents = file.read()
        return file_contents
    except FileNotFoundError:
        return None


def generate_csv_vulnerabilities(vulnerabilities_data):
    """
    Generate a CSV string from a list of vulnerability data.

    Args:
    - vulnerabilities_data (list of dict): List containing dictionaries representing vulnerability data,
      with keys "id", "project", and "description".

    Returns:
    - str: The CSV string containing vulnerability data.
    """
    # Create a StringIO object to store CSV data
    csv_buffer = StringIO()

    fieldnames = ["ID", "Project", "Description"]

    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)

    writer.writeheader()

    for vulnerability in vulnerabilities_data:
        writer.writerow(
            {
                "ID": vulnerability["id"],
                "Project": vulnerability["project"],
                "Description": vulnerability["description"],
            }
        )

    csv_string = csv_buffer.getvalue()

    csv_buffer.close()

    return csv_string


def has_permission_from_token(request, permission_codename):
    """
    Check if the user associated with the request has a specific permission identified by its codename.

    Args:
    - request (HttpRequest): The request object associated with the user.
    - permission_codename (str): The codename of the permission to check.

    Returns:
    - bool: True if the user has the specified permission, False otherwise.
    """
    return request.user.has_perm(permission_codename)
