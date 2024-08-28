from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
from todo.models import Login, User

class CreateUserSerializer(serializers.Serializer):
  first_name = serializers.CharField(max_length=180, required=True)
  last_name = serializers.CharField(max_length=100, required=True)
  email = serializers.EmailField(validators=[UniqueValidator(queryset=Login.objects.all(), message="User already exists")])
  password = serializers.CharField(max_length=300, required=True)


  def create(self, validated_data):
    login = Login(
      email=validated_data['email'],
      password=make_password(validated_data['password'])
    )

    login.save()

    user = User(
      first_name=validated_data['first_name'],
      last_name=validated_data['last_name'],
      login=login
    )
    
    user.save()

    data = {
      'id': login.id,
      'email': login.email,
      'first_name': user.first_name,
      'last_name': user.last_name
    }

    return data

    
