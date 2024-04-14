# Generated by Django 5.0 on 2024-03-06 08:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0020_proxyconfig_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='proxyconfig',
            name='auth_request',
            field=models.TextField(default=' ', max_length=100000, verbose_name='auth request'),
        ),
        migrations.AddField(
            model_name='proxyconfig',
            name='login_name',
            field=models.TextField(default=' ', max_length=100000, verbose_name='login param name'),
        ),
        migrations.AddField(
            model_name='proxyconfig',
            name='password_name',
            field=models.TextField(default=' ', max_length=100000, verbose_name='password param name'),
        ),
        migrations.AddField(
            model_name='proxyconfig',
            name='request_to_csrf',
            field=models.TextField(default=' ', max_length=100000, verbose_name='auth request'),
        ),
    ]