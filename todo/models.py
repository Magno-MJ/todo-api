from django.db import models
import uuid

class Login(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4())
    email = models.EmailField(unique=True)
    password = models.CharField(max_length = 300)

    account_activated_at = models.DateTimeField(null = True, default = None)

    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    def __str__(self):
        return "Email: %s" % {self.email,}


class User(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4())
    first_name = models.CharField(max_length = 180)
    last_name = models.CharField(max_length = 100)
    
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    login = models.OneToOneField(Login, on_delete = models.CASCADE)

    def __str__(self):
        return "Nome: %s, Sobrenome: %s" % {self.first_name, self.last_name,}


class Task(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4())
    name = models.CharField(max_length = 180)
    description = models.TextField(max_length = 500)

    completed_at = models.BooleanField(null = True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    user = models.ForeignKey(User, on_delete = models.CASCADE)

    def __str__(self):
        return "Name: %s, Description: %s, Completed At: %s" % {self.name, self.description, self.completed_at}