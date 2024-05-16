# Generated by Django 5.0.4 on 2024-05-14 11:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('judge', '0003_remove_problem_classes_remove_problem_group_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='profile',
            options={'ordering': ['id'], 'verbose_name': 'profile', 'verbose_name_plural': 'profiles'},
        ),
        migrations.AddField(
            model_name='user',
            name='is_superadmin',
            field=models.BooleanField(default=False, verbose_name='superadmin status'),
        ),
    ]
