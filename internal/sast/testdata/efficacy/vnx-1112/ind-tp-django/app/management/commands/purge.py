from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Purge old rows"

    def add_arguments(self, parser):
        parser.add_argument("days", type=int, help="age in days")
~>        parser.add_argument("--skip-verify", action="store_true")
