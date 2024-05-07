from .models import (
    Target,
    Project,
    Risk,
    Vulnerability,
    Risks,
    # RiskAssessment,
    # RiskTreatment,
)
from .models import Scan
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework import serializers
from .models import Tenant, UserProfile, User_Otp, Tenant_user, UserCustom
from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group, Permission


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ("name", "useruuid_id")


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("email", "password", "tenant", "is_verified", "mfa_code")


class User_OtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_Otp
        fields = ["otp", "is_active", "useruuid"]


class User_LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.

    This serializer validates email and password provided for user login. It checks
    if the credentials are correct by authenticating the user with the provided email
    and password using Django's authentication system. If authentication fails, it raises
    a validation error with the message "Incorrect email or password".

    Attributes:
    - email (EmailField): Field for user email.
    - password (CharField): Field for user password.

    Methods:
    - validate(data): Method to validate email and password and authenticate the user.
      Raises a validation error if authentication fails.
    """

    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError("Incorrect email or password")

        data["user"] = user

        return data


class TenantUserSerializer(serializers.ModelSerializer):
    """
    Serializer for tenant user data.

    This serializer is used to serialize and validate data for tenant users.
    It includes fields for the tenant ID, name, organization name, and active status.

    Attributes:
    - id (ReadOnlyField): Field for the unique identifier of the tenant user.
    - tenant_id (PrimaryKeyRelatedField): Field for the ID of the associated tenant.
    - name (CharField): Field for the name of the tenant user.
    - organization_name (CharField): Field for the organization name of the tenant user.
    - is_active (BooleanField): Field for the active status of the tenant user.

    Methods:
    - validate_name(value): Method to validate the name field. Raises a validation error
      if the name is empty.
    - validate_organization_name(value): Method to validate the organization name field.
      Raises a validation error if the organization name is empty.
    - validate_is_active(value): Method to validate the is_active field. Raises a validation
      error if the value is not a boolean.
    """

    class Meta:
        model = Tenant_user
        fields = ["id", "tenant_id", "name", "organization_name", "is_active"]

    def validate_name(self, value):
        if not value:
            raise serializers.ValidationError("Name cannot be empty")
        return value

    def validate_organization_name(self, value):
        if not value:
            raise serializers.ValidationError("Organization name cannot be empty")
        return value

    def validate_is_active(self, value):
        if not isinstance(value, bool):
            raise serializers.ValidationError("is_active must be a boolean value")
        return value


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user data.

    This serializer is used to serialize and validate user data, including email
    and full name fields.

    Attributes:
    - email (EmailField): Field for the user's email address.
    - full_name (CharField): Field for the user's full name.

    Methods:
    - validate_email(value): Method to validate the email field. It checks if the email
      address is valid and if it's already in use by another user.
    - validate_full_name(value): Method to validate the full name field. It checks if the
      full name contains both first name and last name.
    """

    email = serializers.EmailField(required=True)
    full_name = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = User
        fields = ("email", "full_name")

    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already exists")

        return value

    def validate_full_name(self, value):
        name_parts = value.split()
        if len(name_parts) < 2:
            raise serializers.ValidationError(
                "Full name should contain both first name and last name"
            )

        return value


class GroupSerializer(serializers.ModelSerializer):
    """
    Serializer for group data.

    This serializer is used to serialize and update group data, including
    the group's name and associated permissions.

    Attributes:
    - id (ReadOnlyField): Field for the unique identifier of the group.
    - name (CharField): Field for the name of the group.
    - permission_names (SerializerMethodField): Method field to retrieve the names
      of permissions associated with the group.

    Methods:
    - get_permission_names(group): Method to retrieve the names of permissions associated
      with the group.
    - update(instance, validated_data): Method to update the group instance with the
      provided validated data, including the name and associated permissions.
    - assign_roles(group, permission_names): Method to assign permissions to the group.
    """

    permission_names = serializers.SerializerMethodField()

    def get_permission_names(self, group):
        return list(group.permissions.values_list("name", flat=True))

    class Meta:
        model = Group
        fields = ["id", "name", "permission_names"]

    def update(self, instance, validated_data):
        instance.name = validated_data.get("name", instance.name)
        instance.save()

        permission_names = validated_data.get("permission_names", [])
        self.assign_roles(instance, permission_names)

        return instance

    def assign_roles(self, group, permission_names):
        group.permissions.clear()

        for permission_name in permission_names:
            try:
                permission = Permission.objects.get(name=permission_name)
                group.permissions.add(permission)
            except Permission.DoesNotExist:
                pass


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCustom
        fields = ["id", "username", "email", "tenant", "is_active"]


class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = "__all__"


class ProjectSerializer(serializers.ModelSerializer):
    targets = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Target.objects.all()
    )

    class Meta:
        model = Project
        fields = "__all__"

    def create(self, validated_data):
        """
        Create a new project instance.
        """
        targets_data = validated_data.pop("targets")
        project = Project.objects.create(**validated_data)
        project.targets.set(targets_data)
        return project

    def to_representation(self, instance):
        """
        Convert model instance to a Python dictionary for serialization.
        """
        representation = super().to_representation(instance)
        representation["targets"] = TargetSerializer(
            instance.targets.all(), many=True
        ).data
        return representation


class RiskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Risk
        fields = ["id", "project", "description"]


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ["id", "project", "description"]


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = "__all__"


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ("id", "name", "codename", "content_type")


class RisksSerializer(serializers.ModelSerializer):
    class Meta:
        model = Risks
        fields = "__all__"


# class RiskAssessmentSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = RiskAssessment
#         fields = "__all__"


# class RiskTreatmentSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = RiskTreatment
#         fields = "__all__"


# class ProjectTargetSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = ProjectTarget
#         fields = [
#             "id",
#             "target_name",
#             "target_description",
#         ]


# class ProjectSerializer(serializers.ModelSerializer):
#     """
#     Serializer for project data.

#     This serializer is used to serialize and update project data, including
#     the project's name, description, associated targets, and retest status.

#     Attributes:
#     - id (ReadOnlyField): Field for the unique identifier of the project.
#     - name (CharField): Field for the name of the project.
#     - description (CharField): Field for the description of the project.
#     - targets (ProjectTargetSerializer): Serializer for the project's targets.
#     - retest (BooleanField): Field indicating the retest status of the project.

#     Methods:
#     - create(validated_data): Method to create a new project instance with the provided
#       validated data, including the project's name, description, and associated targets.
#     - update(instance, validated_data): Method to update an existing project instance
#       with the provided validated data.
#     """

#     targets = ProjectTargetSerializer(many=True)

#     class Meta:
#         model = Project
#         fields = ["id", "name", "description", "targets", "retest"]

#     def create(self, validated_data):
#         targets_data = validated_data.pop("targets", [])
#         project = Project.objects.create(**validated_data)
#         for target_data in targets_data:
#             ProjectTarget.objects.create(project=project, **target_data)
#         return project

#     def update(self, instance, validated_data):
#         # Update fields of the Project instance
#         instance.name = validated_data.get("name", instance.name)
#         instance.description = validated_data.get("description", instance.description)
#         instance.retest = validated_data.get("retest", instance.retest)

#         # Update associated targets if provided
#         targets_data = validated_data.get("targets", [])
#         for target_data in targets_data:
#             target_id = target_data.get("id", None)
#             if target_id:
#                 target_instance = instance.targets.filter(id=target_id).first()
#                 if target_instance:
#                     # Update existing target
#                     target_instance.field1 = target_data.get(
#                         "field1", target_instance.field1
#                     )
#                     target_instance.field2 = target_data.get(
#                         "field2", target_instance.field2
#                     )
#                     # Update other fields similarly
#                     target_instance.save()
#                 else:
#                     # Create new target if it doesn't exist
#                     ProjectTarget.objects.create(project=instance, **target_data)

#         instance.save()
#         return instance
