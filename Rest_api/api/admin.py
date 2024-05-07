from django.contrib import admin
from .models import *

admin.site.register(Tenant)
admin.site.register(UserProfile)
admin.site.register(User_Otp)
admin.site.register(BlacklistedToken)
admin.site.register(Tenant_user)
admin.site.register(Target)
admin.site.register(UserCustom)
admin.site.register(Project)
admin.site.register(Risk)
admin.site.register(Vulnerability)
admin.site.register(Scan)
admin.site.register(Risks)
# admin.site.register(RiskAssessment)
# admin.site.register(RiskTreatment)
