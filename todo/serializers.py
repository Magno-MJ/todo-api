from datetime import datetime
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from todo.models import Login, Todo, User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed


class CreateUserSerializer(serializers.Serializer):
  first_name = serializers.CharField(max_length=180, required=True)
  last_name = serializers.CharField(max_length=100, required=True)
  email = serializers.EmailField(validators=[UniqueValidator(queryset=Login.objects.all(), message="User already exists")])
  password = serializers.CharField(max_length=300, required=True)


  def create(self, validated_data):
    login = Login(
      email=validated_data['email'],
      password=validated_data['password']
    )

    login.set_password(login.password)

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



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
  def validate(self, attrs):
    login = Login.objects.get(email = attrs.get('email'))

    if login.account_activated_at == None:
      raise AuthenticationFailed("Account not activated")
    
    data = super().validate(attrs)

    refresh = self.get_token(self.user)

    data["refresh"] = str(refresh)
    data["access"] = str(refresh.access_token)

    login.last_login = datetime.now()
    login.save()

    return data
  

class CreateTodoSerializer(serializers.Serializer):
  name = serializers.CharField(max_length=180, required=True)
  description = serializers.CharField(max_length=100, required=True)


class UpdateTodoSerializer(serializers.Serializer):
  name = serializers.CharField(max_length=180, required=True)
  description = serializers.CharField(max_length=100, required=False)


class TodoSerializer(serializers.ModelSerializer):
  user_id = serializers.UUIDField(source='user.id')
  class Meta:
    model = Todo
    exclude = ['user']

