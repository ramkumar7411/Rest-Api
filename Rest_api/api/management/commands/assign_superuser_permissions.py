from django.contrib.auth.models import User, Group, Permission
from django.core.management.base import BaseCommand
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    """
    Command to assign admin role and permissions to the superuser.

    This command retrieves the superuser, creates an admin group if it doesn't exist,
    adds the superuser to the admin group, assigns all permissions to the admin group,
    generates access and refresh tokens for the superuser, and stores the tokens with
    the user and in the Django auth token model.

    Usage:
    python manage.py assign_admin_role

    """

    help = "Assign admin role and permissions to superuser"

    def handle(self, *args, **options):
        # Retrieve the superuser
        superuser = User.objects.get(username="admin")

        # Retrieve or create the admin group
        admin_group, created = Group.objects.get_or_create(name="admin")

        # Add the superuser to the admin group
        superuser.groups.add(admin_group)

        # Retrieve all permissions
        all_permissions = Permission.objects.all()

        # Add all permissions to the admin group
        admin_group.permissions.set(all_permissions)

        self.stdout.write(
            self.style.SUCCESS(
                'Successfully assigned admin role and permissions to the superuser and added to "admin" group'
            )
        )
        # Store the tokens directly with the user
        # Generate Access Token
        access_token = AccessToken.for_user(superuser)
        # Generate Refresh Token
        refresh_token = RefreshToken.for_user(superuser)
        superuser.access_token = str(access_token)
        superuser.refresh_token = str(refresh_token)
        superuser.save()
        token, created = Token.objects.get_or_create(user=superuser)
        if not created:
            # Token record already exists, update it
            token.key = str(access_token)
            token.save()
        self.stdout.write(
            self.style.SUCCESS("JWT Access Token: {}".format(access_token))
        )
        self.stdout.write(
            self.style.SUCCESS("JWT Refresh Token: {}".format(refresh_token))
        )
