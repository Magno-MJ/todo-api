from django.urls import path
from rest_framework import permissions
from todo.views import (ConfirmAccountView, CreateUserView, CustomTokenObtainPairView,
  ListCreateTodoView, RetrieveUpdateDestroyTodoView)
from rest_framework_simplejwt.views import (
  TokenRefreshView,
)
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
  openapi.Info(
    title="TO-DO API",
    default_version='v1',
    description="API to manage user's to-do's",
  ),
  public=True,
  permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
  path('swagger<format>/', schema_view.without_ui(), name='schema-json'),
  path('swagger/', schema_view.with_ui('swagger'), name='schema-swagger-ui'),
  path('redoc/', schema_view.with_ui('redoc'), name='schema-redoc'),
  path('user/register', CreateUserView.as_view()),
  path('confirm-account', ConfirmAccountView.as_view()),
  path('login', CustomTokenObtainPairView.as_view()),
  path('refresh-token', TokenRefreshView.as_view()),
  path('todo', ListCreateTodoView.as_view()),
  path('todo/<str:pk>', RetrieveUpdateDestroyTodoView.as_view())
]