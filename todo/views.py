from rest_framework.views import APIView
from rest_framework.response import Response
from todo.serializers import CreateUserSerializer
from django.core.mail import send_mail
from django.conf import settings
from cryptocode import encrypt, decrypt
from rest_framework import status
from datetime import datetime
from rest_framework.exceptions import NotFound, ValidationError
from todo.models import Login

class CreateUserView(APIView):
  def post(self, request):
    serializer = CreateUserSerializer(data=request.data)

    serializer.is_valid(raise_exception=True)
    created_user = serializer.save()

    user_token = encrypt(str(created_user.get('id')), settings.SECRET_KEY)

    send_mail(
      'Confirmação de Conta',
      'Token de confirmação: %s' % user_token,
      'todo-api@mail.com',
      [created_user.get('email')],
      fail_silently = False,
    )

    return Response(created_user, status=status.HTTP_201_CREATED)
  

class ConfirmAccountView(APIView):
  def post(self, request):

    token = request.query_params.get('token')

    if token == None:
      raise ValidationError("Token is missing")
    
    user_id = decrypt(token, settings.SECRET_KEY)
    
    try:
      login = Login.objects.get(pk=user_id)
      login.account_activated_at = datetime.now()
      login.save()
    except Login.DoesNotExist:
      raise NotFound("User not found")

    return Response()