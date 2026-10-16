from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **opts):
        u = User.objects.create(username="root")
        u.is_superuser = True
        u.is_staff = True
        u.save()
