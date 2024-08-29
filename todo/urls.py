from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from todo.views import ConfirmAccountView, CreateUserView


urlpatterns = [
  path('user/register', CreateUserView.as_view()),
  path('confirm-account', ConfirmAccountView.as_view())
]