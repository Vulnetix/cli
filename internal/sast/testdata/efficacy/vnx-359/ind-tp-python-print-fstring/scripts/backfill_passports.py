from app.models import Traveller


def main():
    for record in Traveller.objects.filter(verified=False):
        record.verify()
~>        print(f"Verified passport {record.passport_number} for {record.full_name}")


if __name__ == "__main__":
    main()
