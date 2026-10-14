from django.db import connection


def test_report(client):
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO shop_product (name, price) VALUES ('a', 1)")
    assert client.get("/report").status_code == 200
