# Generated by Django 5.0 on 2024-03-05 14:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0019_proxyconfig'),
    ]

    operations = [
        migrations.AddField(
            model_name='proxyconfig',
            name='status',
            field=models.TextField(default='stopped', max_length=100, verbose_name='status'),
        ),
    ]
