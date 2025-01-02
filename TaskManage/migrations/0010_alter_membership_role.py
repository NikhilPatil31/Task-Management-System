# Generated by Django 5.1.4 on 2024-12-26 13:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0009_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='membership',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('manager', 'Manager'), ('member', 'Member')], default='admin', max_length=10),
        ),
    ]
