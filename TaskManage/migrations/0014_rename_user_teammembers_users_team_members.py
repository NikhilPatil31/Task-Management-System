# Generated by Django 5.1.4 on 2024-12-30 12:19

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0013_remove_team_members'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teammembers',
            old_name='user',
            new_name='users',
        ),
        migrations.AddField(
            model_name='team',
            name='members',
            field=models.ManyToManyField(related_name='teams', through='TaskManage.TeamMembers', to=settings.AUTH_USER_MODEL),
        ),
    ]
