# Generated by Django 5.1.4 on 2024-12-31 07:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0021_remove_user_role'),
    ]

    operations = [
        migrations.DeleteModel(
            name='User',
        ),
    ]