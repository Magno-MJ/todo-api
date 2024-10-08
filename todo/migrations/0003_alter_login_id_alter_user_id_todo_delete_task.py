# Generated by Django 5.1 on 2024-09-02 17:16

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('todo', '0002_login_groups_login_is_superuser_login_last_login_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='login',
            name='id',
            field=models.UUIDField(default=uuid.UUID('542baa9a-a687-421e-aa31-62b78991f9f0'), primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.UUIDField(default=uuid.UUID('1b3d544a-9325-48c0-adbc-8adf00eeaf92'), primary_key=True, serialize=False),
        ),
        migrations.CreateModel(
            name='Todo',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('aa477c52-6fcc-42d8-a741-31737b7b1724'), primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=180)),
                ('description', models.TextField(max_length=500)),
                ('completed_at', models.BooleanField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='todo.user')),
            ],
        ),
        migrations.DeleteModel(
            name='Task',
        ),
    ]
