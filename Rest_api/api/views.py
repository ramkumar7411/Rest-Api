import io
import os
import csv
import random
import string
from reportlab.pdfgen import canvas
from datetime import timedelta
from django.core.files.storage import default_storage
from django.utils.encoding import smart_str
from reportlab.lib.pagesizes import letter

from django.http import Http404
from django.http import HttpResponse
from django.contrib.auth.models import Group, Permission
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.http import JsonResponse
from django.contrib.contenttypes.models import ContentType
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import logout
from django.contrib.auth.models import User, Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string

from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, generics

from .utils import (
    vaildate_email_address,
    create_tenant_response,
    genrate_rendom_code,
    genrate_otp_save_to_db,
    Send_email_via_template,
    generate_tokens,
    verifyOTP,
    generate_csv_vulnerabilities,
)
from Rest_api import settings
from .serializers import (
    ProjectSerializer,
    RiskSerializer,
    VulnerabilitySerializer,
    UserSerializer,
    PermissionSerializer,
    ScanSerializer,
    RisksSerializer,
    TargetSerializer,
    User_LoginSerializer,
    TenantUserSerializer,
    GroupSerializer,
    ChangePasswordSerializer
)
from .models import (
    Scan,
    Risks,
    Project,
    UserCustom,
    Risk,
    Tenant_user,
    Target,
    User,
    User_Otp,
    Tenant,
)
from django.contrib.auth.hashers import check_password

from django.contrib.auth.hashers import check_password
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import ChangePasswordSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated
from .serializers import ChangePasswordSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']

            # Debugging: Print old and new passwords
            print("Old Password:", old_password)
            print("New Password:", new_password)

            # Retrieve user object with fresh data
            user = User.objects.get(pk=user.pk)

            # Debugging: Print hashed password stored in the database
            print("Stored Hashed Password:", user.password)

            # Check if the old password matches the stored hashed password
            if not check_password(old_password, user.password):
                # Debugging: Print result of check_password function
                print("check_password Result:", check_password(old_password, user.password))
                return Response({"error": "Incorrect old password."}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()
            return Response({"success": "Password changed successfully."}, status=status.HTTP_200_OK)
        
        # If the serializer is invalid, return the validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(["POST"])
def register_user(request):
    """
    View function to handle user registration.
    Parameters:
    - request: The HTTP request object containing user email and password.
    Returns:
    - If the registration is successful and OTP is sent, returns a success response.
    - If the email format is incorrect, returns an error response with status code 400.
    - If the password validation fails, returns an error response with status code 400.
    - If the user with the provided email already exists, returns an error response with status code 400.
    - If there is an issue with creating a tenant, returns an error response with status code 400.
    - If there is an issue with OTP generation, returns an error response with status code 201.
    - If there is an issue with SMTP mail, returns an error response with status code 201.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        email = request.POST.get("email")
        username = email.split("@")[0]
        password = request.POST.get("password")
        validate_email = vaildate_email_address(email)
        if not validate_email:
            return Response(
                {"error": "Please enter a correct email address"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email, is_active=True).exists():
            return Response(
                {
                    "type": "error",
                    "tenant_id": "",
                    "serialized_tenant": "",
                    "message": "User with this email already exists",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        elif User.objects.filter(email=email, is_active=False).exists():
            user = User.objects.get(email=email, is_active=False)
            user.username = username
            user.set_password(password)
            user.save()
            mfa_code = genrate_rendom_code(6)
            user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
            optResp = genrate_otp_save_to_db(user_opt, "OTP Generated Successfully")
            if optResp.data["type"] == "success":
                html_content = render_to_string(
                    "email/user/otp_email_template.html", {"otp": mfa_code}
                )
                send_email_Resp = Send_email_via_template(
                    "Verification Code", html_content, [email]
                )
                if send_email_Resp:
                    if not Tenant.objects.filter(useruuid_id=user.id).exists():
                        tenant = Tenant.objects.create(
                            name=f"{email}_tenant", useruuid_id=user.id
                        )
                    else:
                        tenant = Tenant.objects.get(useruuid_id=user.id)

                    return Response(
                        {
                            "code": "success",
                            "tendentResp": tenant.id,
                            "message": "User registered successfully. Verification code sent to your email.",
                        },
                        status=status.HTTP_201_CREATED,
                    )

                else:
                    return Response(
                        {
                            "code": "success",
                            "message": "User information updated successfully. SMTP Mail Issue.",
                        },
                        status=status.HTTP_201_CREATED,
                    )
            else:
                return Response("serialized_data", status=status.HTTP_201_CREATED)

        else:
            user = User.objects.create_user(
                username=username, email=email, password=password, is_active=False
            )
            tendentResp = create_tenant_response(email, user.id)
            if tendentResp.data["type"] == "success":
                mfa_code = genrate_rendom_code(6)
                user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
                optResp = genrate_otp_save_to_db(user_opt, "OTP Generated Successfully")
                if optResp.data["type"] == "success":
                    html_content = render_to_string(
                        "email/user/otp_email_template.html", {"otp": mfa_code}
                    )
                    send_email_Resp = Send_email_via_template(
                        "Verification Code", html_content, [email]
                    )
                    if send_email_Resp:
                        return Response(
                            {
                                "code": "success",
                                "tendentResp": tendentResp.data,
                                "message": "User registered successfully. Verification code sent to your email.",
                            },
                            status=status.HTTP_201_CREATED,
                        )
                    else:
                        return Response(
                            {
                                "code": "success",
                                "tendentResp": tendentResp.data,
                                "message": "User registered successfully. SMTP Mail Issue ",
                            },
                            status=status.HTTP_201_CREATED,
                        )
                else:
                    return Response("serialized_data", status=status.HTTP_201_CREATED)
            else:
                return Response(
                    {"error": tendentResp.data["message"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
    else:
        return Response(
            {"error": "Only POST requests are allowed"},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )


@api_view(["POST"])
def verify_otp(request, user_id):
    """
    View function to verify the OTP (One Time Password) submitted by the user.
    Parameters:
    - request: The HTTP request object containing the OTP.
    - user_id: The ID of the user to verify the OTP for.
    Returns:
    - If OTP verification is successful, returns an access token.
    - If OTP verification fails, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        otp = request.POST.get("otp")

        user = get_object_or_404(User, pk=user_id)

        user_otp = User_Otp.objects.filter(
            useruuid=user, otp=otp, is_active=True
        ).first()
        if user_otp:
            user_otp.is_active = False
            user_otp.save()

            access_token = generate_tokens(user.id)
            if access_token.data["type"] == "success":
                return access_token
        else:
            return Response({"error": "Invalid OTP"}, status=400)
    else:
        return Response({"error": "Method not allowed"}, status=405)


@api_view(["POST"])
def login(request):
    """
    View function to handle user login.
    Parameters:
    - request: The HTTP request object containing user email and password.
    Returns:
    - If the login is successful and OTP is sent, returns a success response.
    - If the email format is incorrect, returns an error response with status code 400.
    - If the password validation fails, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        validate_email = vaildate_email_address(request.POST.get("email"))
        if not validate_email:
            return Response(
                {"error": "Please enter a correct email address"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(request.POST.get("password"))
        except ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        serializer = User_LoginSerializer(data=request.POST)

        if serializer.is_valid():
            user = serializer.validated_data["user"]
            request.session["user_id"] = user.id

            mfa_code = genrate_rendom_code(6)
            user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
            optResp = genrate_otp_save_to_db(user_opt, "Otp Genrated SucessFully")

            if optResp.data["type"] == "success":
                html_content = render_to_string(
                    "email/user/login_opt_template.html", {"otp": mfa_code}
                )
                send_email_Resp = Send_email_via_template(
                    "Verification Code", html_content, [request.POST.get("email")]
                )

                if send_email_Resp:
                    return Response(
                        {
                            "code": "success",
                            "message": "User Logged-in successfully. Verification code sent to your email.",
                        },
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    return Response(
                        {
                            "code": "success",
                            "message": "User Logged-in successfully. SMTP Mail Issue ",
                        },
                        status=status.HTTP_201_CREATED,
                    )
            else:
                return Response("serialized_data", status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(
            {"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    View function to handle user logout and invalidate tokens.
    Parameters:
    - request: The HTTP request object.
    Returns:
    - If the user is successfully logged out and tokens are invalidated, returns a success response.
    - If there is an error during the logout process, returns an error response with status code 400.
    """
    try:
        refresh_token = request.data.get("refresh_token")

        if refresh_token:
            # Flush the session to log the user out
            request.session.flush()

            token = RefreshToken(refresh_token)
            token.blacklist()

            tokens = OutstandingToken.objects.filter(user=token.user)
            tokens.delete()

            logout(request)
        return Response(
            {"message": "User logged out and tokens invalidated successfully"},
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def forgot_password(request):
    """
    View function to handle the forgot password functionality.
    Parameters:
    - request: The HTTP request object containing user email.
    Returns:
    - If the password reset OTP is successfully generated and sent to the user's email, returns a success response.
    - If the user email is invalid or not found, returns an error response with status code 400.
    - If there is an issue with SMTP mail, returns an error response with status code 201.
    - If the request method is not POST, returns an error response with status code 405.
    """
    if request.method == "POST":
        validate_email = vaildate_email_address(request.POST.get("email"))
        if not validate_email:
            return Response(
                {"error": "Please enter a correct email address"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=request.POST.get("email"))
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Generate a random OTP
        mfa_code = genrate_rendom_code(6)

        user_opt = {"otp": mfa_code, "is_active": True, "useruuid": user.id}
        optResp = genrate_otp_save_to_db(user_opt, "Otp Genrated SucessFully")

        if optResp.data["type"] == "success":
            html_content = render_to_string(
                "email/user/reset_password.html",
                {"verification_code": mfa_code, "user_email": user.email},
            )
            send_email_Resp = Send_email_via_template(
                "Verification Code", html_content, [request.POST.get("email")]
            )

            if send_email_Resp:
                return Response(
                    {
                        "code": "success",
                        "message": "Forgot Password, Verification code sent to your email.",
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"code": "success", "message": "SMTP Mail Issue "},
                    status=status.HTTP_201_CREATED,
                )
        else:
            return Response("serialized_data", status=status.HTTP_201_CREATED)
    else:
        return Response(
            {"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED
        )


@api_view(["POST"])
def resetpass(request):
    """
    View function to reset the user's password.
    Parameters:
    - request: The HTTP request object containing the email, new_password, confirm_password, and OTP.
    Returns:
    - If the password reset is successful, returns a success response.
    - If there are validation errors (e.g., incorrect email format, weak password), returns error messages with status code 400.
    - If the OTP is invalid or expired, returns an error response with status code 400.
    - If the request method is not POST, returns an error response with status code 405.
    """

    if request.method == "POST":
        email = request.POST.get("email")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        otp = request.POST.get("otp")
        validate_email = vaildate_email_address(email)
        if not validate_email:
            return Response(
                {"error": "Please enter a correct email address"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        errors = {}
        try:
            validate_password(new_password)
        except ValidationError as e:
            errors["new_password"] = e.messages
        try:
            validate_password(confirm_password)
        except ValidationError as e:
            errors["confirm_password"] = e.messages
        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_password:
            raise serializers.ValidationError(
                "New password and confirm password do not match"
            )
        try:
            user = User.objects.get(email=email)
            verify_req = verifyOTP(otp)
            if verify_req.data["type"] == "success":
                user.set_password(new_password)
                user.save()
                return Response(
                    {"error": "Password Changed Successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Invalid or expired OTP!! Please enter the correct OTP"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    else:
        return Response(
            {"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED
        )


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def fetch_own_profile(request):
    """
    Endpoint to fetch the profile of the currently authenticated user.
    """
    user = request.user
    return Response(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }
    )


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def user_list_create(request):
    """
    Handle GET and POST requests for listing and creating users.

    Args:
    - request: The HTTP request object.

    Returns:
    - Response: A JSON response containing either a list of serialized users
      (in case of a GET request) or the serialized data of the created user
      (in case of a POST request).

    GET Request:
        Retrieves a list of serialized users.

    POST Request:
        Creates a new user using provided data. If the user is not authenticated,
        returns a 401 Unauthorized response.

    """
    if request.method == "GET":
        users = UserCustom.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    elif request.method == "POST":
        if not request.user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        tenant = request.user.tenant_set.first()
        tenant_id = tenant.id if tenant else None
        mutable_data = request.data.copy()
        mutable_data["tenant"] = tenant_id
        serializer = UserSerializer(data=mutable_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "PATCH", "DELETE"])
def user_detail(request, pk, **kwargs):
    """
    Handle GET, PUT, PATCH, and DELETE requests for individual users.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the user.

    Returns:
    - Response: A JSON response containing the serialized data of the user
      (in case of a GET request), the updated serialized data of the user
      (in case of a PUT or PATCH request), or a success message indicating
      user deactivation (in case of a DELETE request).

    GET Request:
        Retrieve serialized data of the user.

    PUT or PATCH Request:
        Update the user's data with the provided data.

    DELETE Request:
        Deactivate the user by marking them as inactive.

    """
    try:
        user = UserCustom.objects.get(pk=pk)
    except UserCustom.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    if request.method == "GET":
        serializer = UserSerializer(user)
        return Response(serializer.data)
    elif request.method in ["PUT", "PATCH"]:
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == "DELETE":
        try:
            user = UserCustom.objects.get(id=pk)
            print("user id get", user)
        except UserCustom.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        # Soft delete: Mark user as inactive
        user.is_active = False
        user.save()
        return Response(
            {"message": "User deactivated successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )


class TenantRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    A view for retrieving, updating, and deleting a specific Tenant_user instance.

    Supported HTTP Methods:
    - GET: Retrieve a specific Tenant_user instance or list all Tenant_user instances.
    - POST: Create a new Tenant_user instance.
    - PATCH: Update a specific Tenant_user instance.
    - DELETE: Delete a specific Tenant_user instance.

    Attributes:
    - queryset: The queryset of Tenant_user instances.
    - serializer_class: The serializer class used for Tenant_user instances.
    - lookup_field: The lookup field for retrieving Tenant_user instances.
    """

    queryset = Tenant_user.objects.all()
    serializer_class = TenantUserSerializer
    lookup_field = "tenant_id"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            instance = serializer.save()
            return Response(
                {
                    "code": "success",
                    "message": "Tenant is Successfully Created",
                    "data": [serializer.data],
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": "error",
                "message": "Please fix the validation errors",
                "data": [serializer.errors],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def get(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            try:
                queryset = self.get_queryset().filter(tenant_id=tenant_id)
                serializer = self.get_serializer(queryset, many=True)
                return Response(
                    {
                        "code": "success",
                        "message": "tenants are retrieved",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except ObjectDoesNotExist:
                return Response(
                    {
                        "code": "error",
                        "message": "Tenant_user does not exist for this ID",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(
                {
                    "code": "success",
                    "message": "All tenants are retrieved",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

    def patch(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "code": "success",
                        "message": "Tenant is successfully updated",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "code": "error",
                        "message": "Please fix the validation errors",
                        "data": serializer.errors,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"code": "error", "message": "Provide the Tenant ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def delete(self, request, *args, **kwargs):
        tenant_id = kwargs.get("tenant_id")
        if tenant_id:
            instance = get_object_or_404(Tenant_user, tenant_id=tenant_id)
            instance.delete()
            return Response(
                {"code": "success", "message": "Tenant successfully deleted"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"code": "error", "message": "Provide the Tenant ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class RoleRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    A view for retrieving, updating, and deleting a specific Tenant_user instance.

    Supported HTTP Methods:
    - GET: Retrieve a specific Tenant_user instance or list all Tenant_user instances.
    - POST: Create a new Tenant_user instance.
    - PATCH: Update a specific Tenant_user instance.
    - DELETE: Delete a specific Tenant_user instance.

    Attributes:
    - queryset: The queryset of Tenant_user instances.
    - serializer_class: The serializer class used for Tenant_user instances.
    """

    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    def post(self, request, *args, **kwargs):
        group_name = request.data.get("name")
        permission_names = request.data.get("permission")
        if not group_name or not permission_names:
            return Response(
                {"error": "Role name and permissions are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            group = Group.objects.get(name=group_name)
            return Response(
                {"error": "Role with this name already exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Group.DoesNotExist:
            pass
        try:
            group, created = Group.objects.get_or_create(name=group_name)
            group.permissions.clear()
            permissions = Permission.objects.filter(name__in=permission_names)
            for permission in permissions:
                group.permissions.add(permission)
            serializer = GroupSerializer(group)
            return Response(
                {"success": "Role created successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        except Permission.DoesNotExist:
            return Response(
                {"error": "One or more permissions do not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        group_id = kwargs.get("pk")
        if group_id:
            try:
                group = get_object_or_404(Group, pk=group_id)
                serializer = GroupSerializer(group)
                return Response(
                    {
                        "success": "Role retrieved successfully",
                        "data": [serializer.data],
                    },
                    status=status.HTTP_200_OK,
                )
            except Group.DoesNotExist:
                return Response(
                    {"error": "Role does not exist for this ID"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            try:
                all_groups = Group.objects.all()

                serializer = GroupSerializer(all_groups, many=True)
                return Response(
                    {
                        "success": "Role retrieved successfully",
                        "groups": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

    def put(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        kwargs["partial"] = True
        group_id = kwargs.get("pk")
        if group_id:
            group_name = request.data.get("name")
            permission_names = request.data.get("permission_names")
            if not group_name or not permission_names:
                return Response(
                    {"error": "Role name and permissions are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                group = Group.objects.get(pk=group_id)
                print("group :", group)
                group.permissions.clear()
                permissions = Permission.objects.filter(name__in=permission_names)
                group.permissions.add(*permissions)
                serializer = GroupSerializer(group)
                return Response(
                    {"success": "Role created Updated", "data": [serializer.data]},
                    status=status.HTTP_200_OK,
                )
            except Group.DoesNotExist:
                return Response(
                    {"error": "Group does not exist for this ID"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            return Response("Provide the Role  ID ", status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        group_id = kwargs.get("pk")
        if group_id:
            group = get_object_or_404(Group, pk=group_id)
            permissions = group.permissions.all()
            permissions = [permission.name for permission in permissions]
            group.delete()
            return Response(
                {
                    "success": f"Group with ID {group_id} deleted successfully along with permissions: {permissions}"
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response("Provide the Role  ID ", status=status.HTTP_400_BAD_REQUEST)


class TargetAPIView(APIView):
    """
    A view to handle CRUD operations for Target instances.

    Supported HTTP Methods:
    - GET: Retrieve all Target instances or a specific Target instance by ID.
    - POST: Create a new Target instance.
    - PUT: Update a specific Target instance.
    - DELETE: Mark a specific Target instance as deleted.
    """

    def get(self, request, pk=None):
        if pk:
            target = get_object_or_404(Target, pk=pk, deleted=False)
            serializer = TargetSerializer(target)
            return Response(
                {
                    "code": "success",
                    "message": "Target are retrieved by Target ID",
                    "data": [serializer.data],
                },
                status=status.HTTP_200_OK,
            )
        else:
            targets = Target.objects.all()
            serializer = TargetSerializer(targets, many=True)
            return Response(
                {
                    "code": "success",
                    "message": "Target are retrieved",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

    def post(self, request):
        serializer = TargetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": "success",
                    "message": "Target is Successfully Created",
                    "data": [serializer.data],
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {
                "code": "error",
                "message": "Please fix the validation errors",
                "data": [serializer.errors],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def put(self, request, pk):
        target = get_object_or_404(Target, pk=pk)
        serializer = TargetSerializer(target, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "code": "success",
                    "message": "Target is successfully updated",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "code": "error",
                "message": "Please fix the validation errors",
                "data": [serializer.errors],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    def delete(self, request, pk):
        target = get_object_or_404(Target, pk=pk)
        target.deleted = True
        target.deleted_at = timezone.now()
        target.save()
        return Response(
            {
                "code": "success",
                "message": "Target with ID {} has been deleted.".format(pk),
            },
            status=status.HTTP_200_OK,
        )


@csrf_exempt
def invite_user(request):
    """
    Handle invitation of a user via email.

    This function validates and processes POST requests to send invitation emails to users.

    Args:
    - request: The HTTP request object.

    Returns:
    - JsonResponse: A JSON response indicating the success or failure of the invitation process.
    """
    if request.method == "POST":
        data = request.POST
        email = data.get("email")
        if email:
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({"error": "Invalid email address"}, status=400)

            invite_code = "".join(
                random.choices(string.ascii_letters + string.digits, k=8)
            )
            send_invitation_email(email, invite_code)
            validity_timestamp = timezone.now() + timedelta(minutes=5)
            return JsonResponse(
                {
                    "message": "Invitation sent successfully",
                    "invite_code": invite_code,
                    "validity_timestamp": validity_timestamp,
                }
            )
        else:
            return JsonResponse({"error": "Email address not provided"}, status=400)
    else:
        return JsonResponse({"error": "Only POST requests are allowed"}, status=405)


def send_invitation_email(email, invite_code):
    """
    Send an invitation email to the specified email address.

    Args:
    - email (str): The recipient's email address.
    - invite_code (str): The invitation code to include in the email.

    Returns:
    - None
    """
    subject = "Invitation to join our platform"
    message = f"Hi,\n\nYou have been invited to join our platform. Your invitation code is: {invite_code}"
    send_mail(subject, message, "your_email@example.com", [email], fail_silently=False)


@api_view(["GET"])
def view_risks(request, pk):
    """
    Retrieve risks associated with a specific project.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - Response: A JSON response containing either serialized data of the risks
      associated with the project or a message indicating no risks found.

    """
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return Response(
            {"message": "Project not found."}, status=status.HTTP_404_NOT_FOUND
        )
    risks = Risk.objects.filter(project=project)
    if risks.exists():
        serializer = RiskSerializer(risks, many=True)
        return Response(serializer.data)
    else:
        return Response(
            {"message": "No risks found for this project."},
            status=status.HTTP_404_NOT_FOUND,
        )


@api_view(["GET"])
def export_vulnerabilities_csv(request, pk):
    """
    Export vulnerabilities associated with a specific project to CSV format.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - HttpResponse: A CSV file attachment containing serialized data of the vulnerabilities
      associated with the project.

    """

    if pk:
        try:
            project = Project.objects.get(pk=pk)
            vulnerabilities = project.vulnerabilities.all()
            serializer = VulnerabilitySerializer(vulnerabilities, many=True)
            filetype = request.GET.get("filetype")
            file_path = 'addresses.csv'
            try:
                with default_storage.open(file_path, 'rb') as file:
                    file_contents = file.read()
            except FileNotFoundError:
                return HttpResponse("File not found.", status=404)

            response = HttpResponse(file_contents, content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="{smart_str(file_path)}"'
            return response
        except Project.DoesNotExist:
            return Response(
                {"code": "error", "message": "Project not found. by this project id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    else:
        return Response(
            {"error": "Provide the Project ID"}, status=status.HTTP_404_NOT_FOUND
        )


@api_view(["GET"])
def download_project_report(request, pk):
    """
    Download a project report in PDF format.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - HttpResponse: A PDF file attachment containing serialized data of the project.

    """
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return Response(
            {"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND
        )

    serializer = ProjectSerializer(project)
    file_path = 'TEMP-PDF-Document.pdf'
    try:
            with default_storage.open(file_path, 'rb') as file:
                file_contents = file.read()
    except FileNotFoundError:
                    return HttpResponse("File not found.", status=404)
    response = HttpResponse(file_contents, content_type='tpplication/pdf')
    response["Content-Disposition"] = f'attachment; filename="project_{pk}_report.pdf"'
    return response


@api_view(["PATCH"])
def update_retest_status(request, pk):
    """
    Update the retest status of a project.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the project.

    Returns:
    - Response: A JSON response indicating the success or failure of updating the retest status.

    """
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return Response(
            {"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND
        )
    project.retest = True
    project.save()
    return Response(
        {"message": "Retest status updated successfully"}, status=status.HTTP_200_OK
    )

@api_view(["GET", "POST"])
def scan_list(request):
    """
    Handle GET and POST requests for a list of scans.

    - GET Request:
        Retrieve a list of serialized scans.

    - POST Request:
        Create a new scan using provided data.

    """
    if request.method == "GET":
        scans = Scan.objects.all()
        serializer = ScanSerializer(scans, many=True)
        return Response(serializer.data)
    elif request.method == "POST":
        serializer = ScanSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Scan created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanDetail(APIView):
    """
    A view to handle CRUD operations for individual scans.

    Methods:
    - get_object: Retrieves a Scan instance by its primary key.
    - get: Handles HTTP GET requests to retrieve a specific scan.
    - put: Handles HTTP PUT requests to update a specific scan.
    - patch: Handles HTTP PATCH requests to partially update a specific scan.
    - delete: Handles HTTP DELETE requests to mark a specific scan as deleted.
    """

    def get_object(self, pk):
        try:
            scan = Scan.objects.get(pk=pk)
            if scan.is_deleted:
                raise Http404
            return scan
        except Scan.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        try:
            scan = self.get_object(pk)
            serializer = ScanSerializer(scan)
            return Response(serializer.data)
        except Http404:
            return Response(
                {"message": "Scan ID not found"}, status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, pk):
        scan = self.get_object(pk)
        serializer = ScanSerializer(scan, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Updated succesfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        scan = self.get_object(pk)
        serializer = ScanSerializer(scan, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Updated succesfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        scan = self.get_object(pk)
        scan.is_deleted = True
        scan.save()
        return Response(
            {"message": "Deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


@authentication_classes([JWTAuthentication])
class PermissionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    def post(self, request, *args, **kwargs):
        if not request.user.has_perm("auth.add_permission"):
            return Response(
                {"error": "You do not have permission to create permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        permissionname = request.data.get("name")
        codename = request.data.get("codename")
        model_name = request.data.get("model")
        try:
            content_type = ContentType.objects.get(model=model_name)
            permission, created = Permission.objects.get_or_create(
                content_type=content_type, codename=codename, name=permissionname
            )
            if created:
                return Response(
                    {"error": "Permission SuccesSFULLY Created"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {"error": "Permission  already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except ContentType.DoesNotExist:
            return Response(
                {"error": "Content type 'django_content_type' does not exist."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get(self, request, *args, **kwargs):
        if not request.user.has_perm("auth.view_permission"):
            return Response(
                {"error": "You do not have permission to edit permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        permissionid = kwargs.get("pk")
        if permissionid:
            try:
                group = get_object_or_404(Permission, pk=permissionid)
                serializer = PermissionSerializer(group)
                return Response(
                    {
                        "success": "Permission retrieved successfully",
                        "data": [serializer.data],
                    },
                    status=status.HTTP_200_OK,
                )
            except Permission.DoesNotExist:
                return Response(
                    {"code": "error", "message": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            try:
                permissions = Permission.objects.all()
                serializer = PermissionSerializer(permissions, many=True)
                return Response(
                    {
                        "success": "All Permission  retrieved successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            except Exception as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
    def put(self, request, *args, **kwargs):
        if not request.user.has_perm("auth.change_permission"):
            return Response(
                {"error": "You do not have permission to update permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        permission_id = kwargs.get('pk')
        permission_instance = get_object_or_404(Permission, pk=permission_id)
        serializer = self.get_serializer(permission_instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        if not request.user.has_perm("auth.delete_permission"):
            return Response(
                {"error": "You do not have permission to delete permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        permission_id = kwargs.get('pk')
        permission_instance = get_object_or_404(Permission, pk=permission_id)
        permission_instance.delete()
        return Response({"success": "Permission deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class ProjectList(APIView):
    """
    API endpoint for listing all projects or creating a new project.
    """
    def get(self, request, format=None):
        projects = Project.objects.all()
        serializer = ProjectSerializer(projects, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Project created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProjectDetail(APIView):
    """
    API endpoint for retrieving, updating, or deleting a specific project instance.
    """

    def get_object(self, pk):
        try:
            project = Project.objects.get(pk=pk)
            if project.is_deleted:
                raise Http404
            return project
        except Scan.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        try:
            project = self.get_object(pk)
            serializer = ProjectSerializer(project)
            return Response(serializer.data)
        except Http404:
            return Response(
                {"message": "Project ID not found"}, status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, pk, format=None):
        project = self.get_object(pk)
        serializer = ProjectSerializer(project, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Project updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project = self.get_object(pk)
        project.is_deleted = True
        project.save()
        return Response(
            {"message": "Deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


class RisksListCreateAPIView(APIView):
    """
    API endpoint for listing all risks or creating a new risk.
    """

    def get(self, request):
        risks = Risks.objects.all()
        serializer = RisksSerializer(risks, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = RisksSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Risk created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RisksRetrieveUpdateDestroyAPIView(APIView):
    """
    API endpoint for retrieving, updating, or deleting a specific risk instance.
    """

    def get_object(self, pk):
        try:
            risk = Risks.objects.get(pk=pk)
            if risk.is_deleted:
                raise Http404
            return risk
        except Risks.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        risk = self.get_object(pk)
        serializer = RisksSerializer(risk)
        return Response(serializer.data)

    def put(self, request, pk):
        risk = self.get_object(pk)
        serializer = RisksSerializer(risk, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        risk = self.get_object(pk)
        risk.is_deleted = True
        risk.save()
        return Response(
            {"message": "Deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )

@api_view(["GET"])
def download_scan_report(request, pk):
    """
    Download a scan report in PDF format.

    Args:
    - request: The HTTP request object.
    - pk: The primary key of the scan.

    Returns:
    - HttpResponse: A PDF file attachment containing serialized data of the scan.

    """
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    file_path = f'scan_{pk}_report.pdf'
    if not default_storage.exists(file_path):
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        p.drawString(100, 750, f"Scan ID: {scan.pk}")
        p.drawString(100, 730, f"Scan Engines: {scan.scan_engines}")
        p.drawString(100, 710, f"Scan Schedule: {scan.scan_schedule}")
        p.drawString(100, 690, f"Start Time: {scan.start_time}")
        p.save()
        with default_storage.open(file_path, 'wb') as file:
            file.write(buffer.getvalue())

        try:
            with default_storage.open(file_path, 'rb') as file:
                file_contents = file.read()
        except FileNotFoundError:
            return HttpResponse("File not found.", status=404)

        response = HttpResponse(file_contents, content_type='application/pdf')
        response["Content-Disposition"] = f'attachment; filename="{file_path}"'
        return response


class DownloadOutputCSVAPIView(APIView):
    """
    API endpoint to download output data of a scan in CSV format.

    Parameters:
        scan_id (int): The ID of the scan for which to download the output CSV.

    Returns:
        HttpResponse: The CSV file containing the output data of the scan.
    """

    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        scan_data = {
            "Scan ID": scan.pk,
            "Targets": scan.targets.name,
            "Scan Engines": scan.scan_engines,
            "Scan Schedule": scan.get_scan_schedule_display(),
            "Start Time": scan.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Is Deleted": "Yes" if scan.is_deleted else "No"
        }

        file_path = os.path.join(settings.BASE_DIR, f'scan_{scan_id}_output.csv')

        with open(file_path, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(scan_data.keys()))
            writer.writeheader()
            writer.writerow(scan_data)
        
        with open(file_path, 'rb') as csv_file:
            response = HttpResponse(csv_file.read(), content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_output.csv"'
        
        return response


# class RiskListCreateAPIView(APIView):
#     def get(self, request):
#         risks = Risks.objects.all()
#         serializer = RisksSerializer(risks, many=True)
#         return Response(serializer.data)

#     def post(self, request):
#         serializer = RisksSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class RiskRetrieveUpdateDestroyAPIView(APIView):
#     def get_object(self, pk):
#         try:
#             return Risks.objects.get(pk=pk)
#         except Risks.DoesNotExist:
#             raise Http404

#     def get(self, request, pk):
#         risk = self.get_object(pk)
#         serializer = RisksSerializer(risk)
#         return Response(serializer.data)

#     def put(self, request, pk):
#         risk = self.get_object(pk)
#         serializer = RisksSerializer(risk, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request, pk):
#         risk = self.get_object(pk)
#         risk.delete()
#         return Response(
#                     {
#                         "success": "Delete data successfully",
#                     },
#                     status=status.HTTP_204_NO_CONTENT,
#                 )


# class RiskAssessmentListCreateAPIView(APIView):
#     def get(self, request):
#         risk_assessments = RiskAssessment.objects.all()
#         serializer = RiskAssessmentSerializer(risk_assessments, many=True)
#         return Response(serializer.data)

#     def post(self, request):
#         serializer = RiskAssessmentSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class RiskAssessmentRetrieveUpdateDestroyAPIView(APIView):
#     def get_object(self, pk):
#         try:
#             return RiskAssessment.objects.get(pk=pk)
#         except RiskAssessment.DoesNotExist:
#             raise Http404

#     def get(self, request, pk):
#         risk_assessment = self.get_object(pk)
#         serializer = RiskAssessmentSerializer(risk_assessment)
#         return Response(serializer.data)

#     def put(self, request, pk):
#         risk_assessment = self.get_object(pk)
#         serializer = RiskAssessmentSerializer(risk_assessment, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request, pk):
#         risk_assessment = self.get_object(pk)
#         risk_assessment.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)

# class RiskTreatmentListCreateAPIView(APIView):
#     def get(self, request):
#         risk_treatments = RiskTreatment.objects.all()
#         serializer = RiskTreatmentSerializer(risk_treatments, many=True)
#         return Response(serializer.data)

#     def post(self, request):
#         serializer = RiskTreatmentSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class RiskTreatmentRetrieveUpdateDestroyAPIView(APIView):
#     def get_object(self, pk):
#         try:
#             return RiskTreatment.objects.get(pk=pk)
#         except RiskTreatment.DoesNotExist:
#             raise Http404

#     def get(self, request, pk):
#         risk_treatment = self.get_object(pk)
#         serializer = RiskTreatmentSerializer(risk_treatment)
#         return Response(serializer.data)

#     def put(self, request, pk):
#         risk_treatment = self.get_object(pk)
#         serializer = RiskTreatmentSerializer(risk_treatment, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request, pk):
#         risk_treatment = self.get_object(pk)
#         risk_treatment.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)


# @api_view(['GET'])
# def download_project_report(request, pk):
#     try:
#         project = Project.objects.get(pk=pk)
#     except Project.DoesNotExist:
#         return Response({'message': 'Project not found'},status=status.HTTP_404_NOT_FOUND)

#     # Serialize project details
#     serializer = ProjectSerializer(project)
#     project_data = serializer.data

#     # Generate PDF
#     buffer = BytesIO()
#     pdf = canvas.Canvas(buffer)

#     # Write project details to PDF
#     x_coordinate = 50  # Increased from 200 to 50
#     y_coordinate = 800
#     for key, value in project_data.items():
#         pdf.drawString(x_coordinate, y_coordinate, f"{key}: {value}")
#         y_coordinate -= 30

#     pdf.save()
#     buffer.seek(0)

#     # Return PDF file as response
#     response = HttpResponse(buffer, content_type='application/pdf')
#     response['Content-Disposition'] = f'attachment; filename="project_{pk}_report.pdf"'
#     return response
