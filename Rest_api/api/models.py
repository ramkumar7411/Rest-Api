from django.db import models
import uuid
import json
from django.contrib.auth.models import User, AbstractUser, Group, Permission
from django.utils import timezone

TYPE_CHOICES = [
    ("Cloud", "Cloud"),
    ("Infra", "Infra"),
    ("Website", "Website"),
    ("Webapp", "Webapp"),
    ("API", "API"),
    ("Mobile", "Mobile"),
]


class Tenant(models.Model):
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100, unique=True)


class UserProfile(models.Model):
    email = models.EmailField(unique=True)
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    tenant_uuid = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, null=True, blank=True
    )


class User_Otp(models.Model):
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    otp = models.CharField(max_length=6)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.otp


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=255, unique=True)
    invalidated_at = models.DateTimeField(auto_now_add=True)


class Tenant_user(models.Model):
    tenant_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(
        max_length=100,
        default="",
    )
    organization_name = models.CharField(max_length=300)
    is_active = models.BooleanField(default=False)

    # def __str__(self):
    #     return self.tenant_id


class Target(models.Model):
    name = models.CharField(max_length=300)
    labels = models.CharField(max_length=300)
    tags = models.CharField(max_length=300)
    target_notes = models.CharField(max_length=300)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    key1 = models.CharField(max_length=300)
    key2 = models.CharField(max_length=300)
    field1 = models.CharField(max_length=300)
    field2 = models.CharField(max_length=300)

    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)


class UserCustom(AbstractUser):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True)
    is_active = models.BooleanField(default=True)
    groups = models.ManyToManyField(Group, related_name="custom_users")
    user_permissions = models.ManyToManyField(Permission, related_name="custom_users")


class Project(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    retest = models.BooleanField(default=False)
    targets = models.ManyToManyField(Target, related_name="project_target")
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Risk(models.Model):
    project = models.ForeignKey(
        Project, related_name="projectrisk", on_delete=models.CASCADE
    )
    description = models.TextField()

    def __str__(self):
        return self.description


class Vulnerability(models.Model):
    project = models.ForeignKey(
        Project, related_name="vulnerabilities", on_delete=models.CASCADE
    )
    description = models.TextField()

    def __str__(self):
        return self.description


class Scan(models.Model):
    SCAN_SCHEDULE_CHOICES = (
        ("One time", "One time"),
        ("Daily", "Daily"),
        ("Weekly", "Weekly"),
        ("Monthly", "Monthly"),
        ("Custom", "Custom"),
    )
    scan_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    targets = models.ForeignKey(Target, on_delete=models.CASCADE)
    scan_engines = models.CharField(max_length=10, choices=TYPE_CHOICES)
    scan_schedule = models.CharField(max_length=10, choices=SCAN_SCHEDULE_CHOICES)
    start_time = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)


class Risks(models.Model):
    SEVERITY_CHOICES = [
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Info", "Info"),
    ]

    TREATMENT_CHOICES = [
        ("Accept", "Accept"),
        ("Mitigate", "Mitigate"),
        ("Avoid", "Avoid"),
        ("Transfer", "Transfer"),
    ]

    title = models.TextField()
    description = models.TextField()
    incoming_severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    remediation = models.TextField()
    references = models.TextField()
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    poc = models.TextField()
    compliances = models.TextField()
    last_detected = models.DateTimeField()
    user_modified_severity = models.CharField(max_length=100)
    ums_datetime = models.DateTimeField()
    ums_notes = models.TextField()
    rt_enum = models.CharField(max_length=20, choices=TREATMENT_CHOICES)
    rt_notes = models.TextField()
    rt_user = models.ForeignKey(User, on_delete=models.CASCADE)
    rt_datetime = models.DateTimeField()
    is_deleted = models.BooleanField(default=False)


# class Risks(models.Model):
#     title = models.CharField(max_length=255)
#     description = models.TextField()
#     severity_choices = [
#         ("Critical", "Critical"),
#         ("High", "High"),
#         ("Medium", "Medium"),
#         ("Low", "Low"),
#         ("Info", "Info"),
#     ]
#     severity = models.CharField(max_length=20, choices=severity_choices)
#     remediation = models.TextField()
#     references = models.TextField()
#     poc = models.TextField()
#     compliances = models.TextField()
#     last_detected = models.DateTimeField()
#     scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
#     project = models.ForeignKey(
#         Project, related_name="viewrisk", on_delete=models.CASCADE
#     )
#     deleted = models.BooleanField(default=False)


# class RiskAssessment(models.Model):
#     risk = models.ForeignKey(Risks, on_delete=models.CASCADE)
#     modified_severity_choices = [
#         ("Critical", "Critical"),
#         ("High", "High"),
#         ("Medium", "Medium"),
#         ("Low", "Low"),
#         ("Info", "Info"),
#     ]
#     modified_severity = models.CharField(
#         max_length=20, choices=modified_severity_choices
#     )
#     notes = models.TextField()
#     datetime = models.DateTimeField(default=timezone.now)
#     user = models.ForeignKey(User, on_delete=models.CASCADE)


# class RiskTreatment(models.Model):
#     risk = models.ForeignKey(Risks, on_delete=models.CASCADE)
#     treatment_type_choices = [
#         ("Accept", "Accept"),
#         ("Mitigate", "Mitigate"),
#         ("Avoid", "Avoid"),
#         ("Transfer", "Transfer"),
#     ]
#     treatment_type = models.CharField(max_length=20, choices=treatment_type_choices)
#     notes = models.TextField()
#     datetime = models.DateTimeField(default=timezone.now)
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
