# Generated by Django 3.1.4 on 2020-12-29 11:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SlaGenerator', '0007_auto_20201229_1203'),
    ]

    operations = [
        migrations.AddField(
            model_name='control',
            name='source',
            field=models.CharField(max_length=500, null=True),
        ),
    ]
