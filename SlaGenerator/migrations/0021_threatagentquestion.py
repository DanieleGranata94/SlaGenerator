# Generated by Django 3.1.4 on 2021-03-26 16:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SlaGenerator', '0020_auto_20210315_1209'),
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatAgentQuestion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('question', models.CharField(max_length=100)),
            ],
        ),
    ]
