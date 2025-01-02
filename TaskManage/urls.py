from django.urls import path
from . import views

from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('registerapi/',views.RegisterView.as_view()),
   path('adminlogin/',views.LoginViewAdmin.as_view()),
   path('managerlogin/',views.LoginViewManager.as_view()),
   path('memberlogin/',views.LoginViewMembers.as_view()),
   path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('createteam/',views.CreateTeamView.as_view()),
   path('addteammember/<int:team_id>',views.AddTeamMembers.as_view()),
   path('removeteammember/<int:team_id>/<int:user_id>',views.RemoveTeamMembers.as_view()),
   path('create/<int:team_id>',views.TaskCreateView.as_view()),
   path('update/<int:team_id>',views.TaskUpdateView.as_view()),
   path('delete/<int:team_id>',views.TaskDeleteView.as_view()),
   path('taskview/<int:team_id>',views.TaskView.as_view()),
   path('sortedtask/',views.TaskSortFilter.as_view())
]
