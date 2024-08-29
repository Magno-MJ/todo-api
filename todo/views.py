from rest_framework.views import APIView
from rest_framework.response import Response
from todo.serializers import CreateUserSerializer
from django.core.mail import send_mail
from django.conf import settings
from cryptocode import encrypt
from rest_framework import status

class CreateUserViewSet(APIView):
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
