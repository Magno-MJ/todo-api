from django.urls import path
from todo.views import (ConfirmAccountView, CreateUserView, CustomTokenObtainPairView,
  ListCreateTodoView, RetrieveUpdateDestroyTodoView)
from rest_framework_simplejwt.views import (
  TokenRefreshView,
)

urlpatterns = [
  path('user/register', CreateUserView.as_view()),
  path('confirm-account', ConfirmAccountView.as_view()),
  path('login', CustomTokenObtainPairView.as_view()),
  path('refresh-token', TokenRefreshView.as_view()),
  path('todo', ListCreateTodoView.as_view()),
  path('todo/<str:pk>', RetrieveUpdateDestroyTodoView.as_view())
]