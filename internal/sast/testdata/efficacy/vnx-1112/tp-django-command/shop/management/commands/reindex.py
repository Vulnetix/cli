from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Rebuild the search index"

    def add_arguments(self, parser):
~>        parser.add_argument("--batch-size", type=int, default=500)

    def handle(self, *args, **options):
        pass
