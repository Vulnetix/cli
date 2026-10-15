from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **options):
        admin = User.objects.create_superuser("admin", "admin@example.com", options["password"])
        admin.groups.add(Group.objects.get(name="Administrators"))
        admin.is_superuser = True
        admin.role = "admin"
        admin.save()
