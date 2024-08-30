from django.urls import path
from todo.views import ConfirmAccountView, CreateTodoView, CreateUserView, CustomTokenObtainPairView
from rest_framework_simplejwt.views import (
  TokenRefreshView,
)

urlpatterns = [
  path('user/register', CreateUserView.as_view()),
  path('confirm-account', ConfirmAccountView.as_view()),
  path('login', CustomTokenObtainPairView.as_view()),
  path('refresh-token', TokenRefreshView.as_view()),
  path('todo', CreateTodoView.as_view())
]