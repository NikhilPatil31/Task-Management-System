# Generated by Django 5.1.4 on 2024-12-31 09:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('TaskManage', '0024_alter_teammembers_team'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teammembers',
            old_name='username',
            new_name='user',
        ),
    ]
