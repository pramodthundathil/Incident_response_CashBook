# Generated by Django 5.0.2 on 2024-03-06 06:43

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Home', '0008_alter_expense_category_alter_expense_user_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apppasswordattempt',
            name='custome',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Home.customuser'),
        ),
    ]
