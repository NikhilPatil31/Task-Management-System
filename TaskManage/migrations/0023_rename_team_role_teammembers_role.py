# Generated by Django 5.1.4 on 2024-12-31 07:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0022_delete_user'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teammembers',
            old_name='team_role',
            new_name='role',
        ),
    ]
