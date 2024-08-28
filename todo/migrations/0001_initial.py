# Generated by Django 5.1 on 2024-08-28 20:25

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Login',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('a2e1b0a5-fa06-482c-a68c-58342e2d1675'), primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=300)),
                ('account_activated_at', models.DateTimeField(default=None, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('da4af34d-71f5-4bae-87e5-d98569555d0f'), primary_key=True, serialize=False)),
                ('first_name', models.CharField(max_length=180)),
                ('last_name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('login', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='todo.login')),
            ],
        ),
        migrations.CreateModel(
            name='Task',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('9d826539-608b-4ec7-bcaa-48b1d8948075'), primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=180)),
                ('description', models.TextField(max_length=500)),
                ('completed_at', models.BooleanField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='todo.user')),
            ],
        ),
    ]