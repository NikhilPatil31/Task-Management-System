# Generated by Django 5.1.4 on 2024-12-30 13:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0015_rename_users_teammembers_user'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teammembers',
            old_name='user',
            new_name='users',
        ),
    ]
