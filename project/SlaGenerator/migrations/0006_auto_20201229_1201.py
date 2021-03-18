# Generated by Django 3.1.4 on 2020-12-29 11:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('SlaGenerator', '0005_attribute_value_acronym'),
    ]

    operations = [
        migrations.AddField(
            model_name='threat_attribute',
            name='threat_scenario',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='threat_attribute',
            name='attribute',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='SlaGenerator.attribute'),
        ),
        migrations.AlterField(
            model_name='threat_attribute',
            name='threat',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='SlaGenerator.threat'),
        ),
    ]
