from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from todo.views import CreateUserViewSet


urlpatterns = [
  path('user', CreateUserViewSet.as_view()),
]