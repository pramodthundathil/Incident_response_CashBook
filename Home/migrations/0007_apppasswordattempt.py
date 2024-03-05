# Generated by Django 5.0.2 on 2024-03-05 18:24

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Home', '0006_alter_customuser_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApppasswordAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('passwordattempt', models.PositiveIntegerField()),
                ('custome', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='Home.customuser')),
            ],
        ),
    ]