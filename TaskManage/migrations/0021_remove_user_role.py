# Generated by Django 5.1.4 on 2024-12-31 07:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0020_rename_user_teammembers_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
    ]
