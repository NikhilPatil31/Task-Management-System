# Generated by Django 5.1.4 on 2024-12-30 13:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0014_rename_user_teammembers_users_team_members'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teammembers',
            old_name='users',
            new_name='user',
        ),
    ]