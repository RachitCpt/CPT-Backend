# Generated by Django 5.1.2 on 2024-10-19 15:04

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='pagemaster',
            name='page_url',
        ),
        migrations.AddField(
            model_name='pagemaster',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='pagemaster',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='rolemaster',
            name='pages',
            field=models.ManyToManyField(related_name='roles', to='users.pagemaster'),
        ),
    ]
