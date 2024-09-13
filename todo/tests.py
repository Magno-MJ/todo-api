from datetime import datetime
from django.test import TestCase
from cryptocode import encrypt
from django.conf import settings
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from todo.models import Login, Todo, User
from todo.serializers import (CreateTodoSerializer, CreateUserSerializer,
  CustomTokenObtainPairSerializer, TodoSerializer, UpdateTodoSerializer)
from django.contrib.auth.hashers import make_password, check_password


class LoginModelTest(TestCase):
  def test_create_login(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password="fake-password"
    )

    self.assertEqual(login.email, "fake@mail.com")
    self.assertEqual(login.password, "fake-password")
    self.assertEqual(login.account_activated_at, None)


class UserModelTest(TestCase):
  def test_create_user(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password="fake-password"
    )

    user = User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    self.assertEqual(user.first_name, "fake")
    self.assertEqual(user.last_name, "fake")
    self.assertEqual(user.login,login)


class TodoModelTest(TestCase):
  def test_create_user(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password="fake-password"
    )

    user = User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    todo = Todo.objects.create(
      name="fake",
      description="fake",
      user=user
    )

    self.assertEqual(todo.name, "fake")
    self.assertEqual(todo.description, "fake")
    self.assertEqual(todo.user, user)


class CreateUserSerializerTest(TestCase):
  def test_create_user_serializer_is_valid(self):
    payload = {
      "first_name": "fake",
      "last_name": "fake",
      "email": "fake@mail.com",
      "password": "fake-password",
    }

    serializer = CreateUserSerializer(data=payload)

    self.assertTrue(serializer.is_valid())


  def test_create_user_serializer_is_invalid(self):
    payload = {
      "email": "fake",
    }

    serializer = CreateUserSerializer(data=payload)

    self.assertFalse(serializer.is_valid())

    self.assertEqual(serializer.errors['first_name'][0].title(), "This Field Is Required.")
    self.assertEqual(serializer.errors['last_name'][0].title(), "This Field Is Required.")
    self.assertEqual(serializer.errors['email'][0].title(), "Enter A Valid Email Address.")
    self.assertEqual(serializer.errors['password'][0].title(), "This Field Is Required.")


  def test_create_user_serializer_create(self):
    payload = {
      "first_name" : "fake",
      "last_name" : "fake",
      "email" : "fake@mail.com",
      "password" : "fake-password",
    }

    serializer = CreateUserSerializer(data=payload)

    serializer.is_valid()
    serializer.save()

    login = Login.objects.get(email="fake@mail.com")

    self.assertEqual(login.email, payload.get("email"))
    self.assertTrue(check_password(payload.get("password"), login.password))


class CustomTokenObtainPairSerializerTest(TestCase):
  def test_validate_custom_token_obtain_pair_serializer_success(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password=make_password("fake-password"),
      account_activated_at=datetime.now()
    )

    User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    attrs = {
      "email": login.email ,
      "password": "fake-password",
    }

    serializer = CustomTokenObtainPairSerializer()

    data = serializer.validate(attrs)

    self.assertTrue(data.get("access") != None)
    self.assertTrue(data.get("refresh") != None)

  def test_validate_custom_token_obtain_pair_serializer_user_not_activated(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password=make_password("fake-password"),
    )

    User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    attrs = {
      "email": login.email ,
      "password": "fake-password",
    }

    serializer = CustomTokenObtainPairSerializer()

    with self.assertRaises(AuthenticationFailed) as context:
      serializer.validate(attrs)
      self.assertTrue("Account not activated" in str(context.exception))

  def test_validate_custom_token_obtain_pair_serializer_wrong_credentials(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password=make_password("fake-password"),
    )

    User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    attrs = {
      "email": login.email ,
      "password": "fake",
    }

    serializer = CustomTokenObtainPairSerializer()

    with self.assertRaises(AuthenticationFailed) as context:
      serializer.validate(attrs)
      self.assertTrue("Incorrect authentication credentials." in str(context.exception))


class CreateTodoSerializerTest(TestCase):

  def test_create_todo_serializer_is_valid(self):
    payload = {
      "name" : "fake",
      "description" : "fake",
    }

    serializer = CreateTodoSerializer(data=payload)

    self.assertTrue(serializer.is_valid())

  def test_create_todo_serializer_is_invalid(self):
    payload = {}

    serializer = CreateTodoSerializer(data=payload)

    self.assertFalse(serializer.is_valid())

    self.assertEqual(serializer.errors["name"][0].title(), "This Field Is Required.")
    self.assertEqual(serializer.errors["description"][0].title(), "This Field Is Required.")


class UpdateTodoSerializerTest(TestCase):

  def test_update_todo_serializer_is_valid(self):
    payload = {
      "name" : "fake",
      "description" : "fake",
    }

    serializer = UpdateTodoSerializer(data=payload)

    self.assertTrue(serializer.is_valid())


  def test_update_todo_serializer_is_invalid(self):
    payload = {
      "name": datetime.now(),
      "description": datetime.now(),
    }

    serializer = UpdateTodoSerializer(data=payload)

    self.assertFalse(serializer.is_valid())

    self.assertEqual(serializer.errors["name"][0].title(), "Not A Valid String.")
    self.assertEqual(serializer.errors["description"][0].title(), "Not A Valid String.")


class TodoSerializerTest(TestCase):

  def test_todo_serializer(self):
    login = Login.objects.create(
      email="fake@mail.com",
      password="fake-password"
    )

    user = User.objects.create(
      first_name="fake",
      last_name="fake",
      login=login,
    )

    todo = Todo.objects.create(
      name="fake",
      description="fake",
      user=user
    )

    serializer = TodoSerializer()

    self.assertDictEqual(serializer.to_representation(todo), {
      "id": str(todo.id),
      "user_id": str(todo.user_id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": todo.completed_at,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })


class CreateUserViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/user/register'

  def test_create_user(self):
    payload = {
      "first_name" : "fake",
      "last_name" : "fake",
      "email" : "fake@mail.com",
      "password" : "fake-password",
    }

    response = self.client.post(self.url, payload, format="json")
    self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    self.assertEqual(response.data, {
      "id": response.data.get("id"),
      "email": payload.get("email"),
      "first_name": payload.get("first_name"),
      "last_name": payload.get("last_name")
    })

class ConfirmAccountViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/confirm-account'
  
  # def test_confirm_account(self):
  #   login = Login.objects.create(email="fake@mail.com", password="fake-password")

  #   User.objects.create(first_name="fake", last_name="fake", login=login)

  #   user_token = encrypt(str(login.id), settings.SECRET_KEY)

  #   response = self.client.post(f'{self.url}?token={user_token}', format="json")

  #   self.assertEqual(response.status_code, status.HTTP_200_OK)
  
  def test_confirm_account_missing_token(self):
    login = Login.objects.create(email="fake@mail.com", password="fake-password")

    User.objects.create(first_name="fake", last_name="fake", login=login)

    response = self.client.post(f'{self.url}', format="json")
    
    self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    self.assertEqual(response.data[0], "Token is missing")
  
  def test_confirm_account_missing_token(self):
    login = Login.objects.create(email="fake@mail.com", password="fake-password")

    User.objects.create(first_name="fake", last_name="fake", login=login)

    response = self.client.post(f'{self.url}', format="json")
    
    self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    self.assertEqual(response.data[0], "Token is missing")
  
  def test_confirm_account_login_not_found(self):
    user_token = encrypt('90fe6144-a1cc-4c71-b236-fda568d286db', settings.SECRET_KEY)
    response = self.client.post(f'{self.url}?token={user_token}', format="json")

    self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    self.assertEqual(response.data.get('detail'), "User not found")


class CustomTokenObtainPairViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/login'

  def test_custom_obtain_pair_view_success(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    payload = {
      "email": login.email,
      "password": "fake-password"
    }

    response = self.client.post(f'{self.url}', payload, format="json")

    self.assertTrue(response.data.get("access") != None)
    self.assertTrue(response.data.get("refresh") != None)

  def test_custom_obtain_pair_view_success(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    payload = {
      "email": login.email,
      "password": "fake-password"
    }

    response = self.client.post(f'{self.url}', payload, format="json")

    self.assertTrue(response.data.get("access") != None)
    self.assertTrue(response.data.get("refresh") != None)


class TokenRefreshViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/refresh-token'

  def test_token_refresh_view_test_success(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    refresh_token = login_response.data.get("refresh")

    payload = {
      "refresh": refresh_token
    }

    response = self.client.post(f'{self.url}', payload, format="json")

    self.assertTrue(response.data.get("access") != None)


class ListCreateTodoViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/todo'

  def test_list_create_todo_view_success_on_create(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    payload = {
      "name": "fake",
      "description": "fake"
    }

    token = login_response.data.get("access")

    response = self.client.post(f'{self.url}', payload, format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": response.data.get("id"),
      "user_id": str(user.id),
      "name": payload.get("name"),
      "description": payload.get("description"),
      "completed_at": None,
      "created_at": response.data.get("created_at"),
      "updated_at": response.data.get("updated_at"),
    })

  def test_list_create_todo_view_success_on_list_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.get(f'{self.url}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data[0], {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })


  def test_list_create_todo_view_success_on_list_to_admin(self):
    admin_login = Login.objects.create(email="fake@admin.com", password=make_password("fake-password"), account_activated_at=datetime.now(), is_superuser=True)
    
    User.objects.create(first_name="fake", last_name="fake", login=admin_login)

    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": admin_login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.get(f'{self.url}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data[0], {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })


class RetrieveUpdateDestroyTodoViewTest(APITestCase):
  def setUp(self) -> None:
    self.url = '/todo'

  def test_retrieve_update_destroy_todo_view_success_on_retrieve_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.get(f'{self.url}/{todo.id}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })

  def test_retrieve_update_destroy_todo_view_not_found_on_retrieve_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.get(f'{self.url}/48c83100-9fbb-44d2-a6e6-92c22dcc5a91', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

  def test_retrieve_update_destroy_todo_view_success_on_retrieve_to_admin(self):
    admin_login = Login.objects.create(email="fake@admin.com", password=make_password("fake-password"), account_activated_at=datetime.now(), is_superuser=True)

    User.objects.create(first_name="fake", last_name="fake", login=admin_login)

    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": admin_login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.get(f'{self.url}/{todo.id}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })

  def test_retrieve_update_destroy_todo_view_success_on_update_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    payload = {
      "name": "updated"
    }

    response = self.client.patch(f'{self.url}/{todo.id}', payload, format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": payload.get("name"),
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": response.data.get("updated_at"),
    })

  def test_list_create_todo_view_not_found_on_update_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    payload = {
      "name": "updated"
    }

    response = self.client.patch(f'{self.url}/48c83100-9fbb-44d2-a6e6-92c22dcc5a91', payload, format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

  def test_list_create_todo_view_success_on_update_to_admin(self):
    admin_login = Login.objects.create(email="fake@admin.com", password=make_password("fake-password"), account_activated_at=datetime.now(), is_superuser=True)

    User.objects.create(first_name="fake", last_name="fake", login=admin_login)

    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": admin_login.email,
      "password": "fake-password" 
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    payload = {
      "name": "updated"
    }

    response = self.client.patch(f'{self.url}/{todo.id}', payload, format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": payload.get("name"),
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": response.data.get("updated_at"),
    })


  def test_retrieve_update_destroy_todo_view_success_on_destroy_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.delete(f'{self.url}/{todo.id}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })

  def test_retrieve_update_destroy_todo_view_not_found_on_destroy_to_user(self):
    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    User.objects.create(first_name="fake", last_name="fake", login=login)

    login_payload = {
      "email": login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.delete(f'{self.url}/48c83100-9fbb-44d2-a6e6-92c22dcc5a91', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

  def test_retrieve_update_destroy_todo_view_success_on_destroy_to_admin(self):
    admin_login = Login.objects.create(email="fake@admin.com", password=make_password("fake-password"), account_activated_at=datetime.now(), is_superuser=True)

    User.objects.create(first_name="fake", last_name="fake", login=admin_login)

    login = Login.objects.create(email="fake@mail.com", password=make_password("fake-password"), account_activated_at=datetime.now())

    user = User.objects.create(first_name="fake", last_name="fake", login=login)

    todo = Todo.objects.create(name="fake", description="fake", user=user)

    login_payload = {
      "email": admin_login.email,
      "password": "fake-password"
    }

    login_response = self.client.post('/login', login_payload, format="json")

    token = login_response.data.get("access")

    response = self.client.delete(f'{self.url}/{todo.id}', format="json", headers={
      "Authorization": f"Bearer {token}"
    })

    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data, {
      "id": str(todo.id),
      "user_id": str(user.id),
      "name": todo.name,
      "description": todo.description,
      "completed_at": None,
      "created_at": todo.created_at.replace(tzinfo=None).isoformat()+'Z',
      "updated_at": todo.updated_at.replace(tzinfo=None).isoformat()+'Z',
    })