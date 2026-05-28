from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0205_add_ordering_to_instancegroup_and_workflow_nodes'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='organization',
            options={
                'default_permissions': ('add', 'change', 'delete', 'view'),
                'ordering': ('name',),
                'permissions': [
                    ('member_organization', 'Basic participation permissions for organization'),
                    ('audit_organization', 'Audit everything inside the organization'),
                ],
            },
        ),
    ]
