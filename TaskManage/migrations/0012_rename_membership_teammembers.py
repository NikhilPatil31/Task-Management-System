# Generated by Django 5.1.4 on 2024-12-30 10:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0011_alter_team_name'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Membership',
            new_name='TeamMembers',
        ),
    ]
