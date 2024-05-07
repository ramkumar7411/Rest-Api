from django.urls import path
from . import views
from api.views import (
    RisksListCreateAPIView,
    RisksRetrieveUpdateDestroyAPIView,
    ProjectList,
    ProjectDetail,
    DownloadOutputCSVAPIView,
    ChangePasswordView
)
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework_simplejwt.views import TokenRefreshView
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="API",
      default_version='v1',
      description="Security Scan Management API",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)
urlpatterns = [
    path('api/v1/auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path("api/v1/auth/register/", views.register_user, name="register_user"),
    path("api/v1/auth/login/", views.login, name="login"),
    path("api/v1/auth/logout/", views.logout_user, name="logout"),
    path("api/v1/auth/forgot-password/", views.forgot_password, name="forgot_password"),
    path("api/v1/auth/reset-password/", views.resetpass, name="reset_password"),
    path("api/v1/auth/verify-otp/<int:user_id>/", views.verify_otp, name="verify_otp"),
    # path("api/v1/auth/me/", views.fetch_own_profile, name="fetch_own_profile"),
    path(
        "api/v1/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"
    ),
    # tenants API
    path(
        "api/v1/tenants/",
        views.TenantRetrieveUpdateDestroyView.as_view(),
        name="tenant",
    ),
    path(
        "api/v1/tenants/<tenant_id>/",
        views.TenantRetrieveUpdateDestroyView.as_view(),
        name="tenant-detail",
    ),
    # user API
    path("api/v1/invite_user/", views.invite_user, name="invite_user"),
    path("api/v1/users/", views.user_list_create, name="user-list"),
    path("api/v1/users/<int:pk>/", views.user_detail, name="user-detail"),
    # Roles API
    path(
        "api/v1/role/",
        views.RoleRetrieveUpdateDestroyView.as_view(),
        name="create_role",
    ),
    path(
        "api/v1/role/<int:pk>/",
        views.RoleRetrieveUpdateDestroyView.as_view(),
        name="get_role_by_id",
    ),
    # Targets API
    path("api/v1/targets/", views.TargetAPIView.as_view(), name="target-list"),
    path(
        "api/v1/targets/<int:pk>/", views.TargetAPIView.as_view(), name="target-detail"
    ),
    path(
        "api/v1/projects/<int:pk>/download-project-report/",
        views.download_project_report,
    ),
    path("api/v1/projects/<int:pk>/retest/", views.update_retest_status),

    # scan API
    path("api/v1/scans/", views.scan_list, name="scans"),
    path("api/v1/scans/<int:pk>/", views.ScanDetail.as_view(), name="scan_detail"),
    path("api/v1/scans/<int:pk>/download-project-report/",views.download_scan_report),
    path('api/v1/scans/<int:scan_id>/download-output-csv/', DownloadOutputCSVAPIView.as_view(), name='download-output-csv'),

    # Permission API
    # path(
    #     "api/v1/permission/",
    #     views.PermissionRetrieveUpdateDestroyView.as_view(),
    #     name="create_permission",
    # ),
    path(
        "api/v1/permission/<int:pk>/",
        views.PermissionRetrieveUpdateDestroyView.as_view(),
        name="view_permission",
    ),
    # project
    path("api/v1/projects/", ProjectList.as_view(), name="project-list"),
    path("api/v1/projects/<int:pk>/", ProjectDetail.as_view(), name="project-detail"),
    path("api/v1/projects/<int:pk>/risks/", views.view_risks),
    path("api/v1/projects/<int:pk>/export/", views.export_vulnerabilities_csv),
    # Risks
    path("api/v1/risks/", RisksListCreateAPIView.as_view(), name="risk-list-create"),
    path(
        "api/v1/risks/<int:pk>/",
        RisksRetrieveUpdateDestroyAPIView.as_view(),
        name="risk-retrieve-update-destroy",
    ),
    #Swager Documentation UI path
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]
