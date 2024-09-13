from django.db import models
import uuid
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from todo.managers import CustomLoginManager

class Login(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length = 300)

    account_activated_at = models.DateTimeField(null = True, default = None)

    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    USERNAME_FIELD = 'email'

    objects = CustomLoginManager()

    def __str__(self):
        return "Email: %s" % {self.email,}


class User(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4)
    first_name = models.CharField(max_length = 180)
    last_name = models.CharField(max_length = 100)
    
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    login = models.OneToOneField(Login, on_delete = models.CASCADE)

    def __str__(self):
        return f'id: {self.id}, first_name: {self.first_name}, last_name: {self.last_name}'


class Todo(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4)
    name = models.CharField(max_length = 180)
    description = models.TextField(max_length = 500)

    completed_at = models.BooleanField(null = True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    user = models.ForeignKey(User, on_delete = models.CASCADE)

    def __str__(self):
        return "Name: %s, Description: %s, Completed At: %s" % {self.name, self.description, self.completed_at}