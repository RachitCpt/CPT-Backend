# Generated by Django 5.1.2 on 2024-11-10 04:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_user_employee_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='employee_id',
        ),
        migrations.AlterField(
            model_name='user',
            name='f_name',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='user',
            name='l_name',
            field=models.CharField(max_length=20),
        ),
    ]