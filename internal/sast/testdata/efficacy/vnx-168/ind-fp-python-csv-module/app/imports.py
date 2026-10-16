import csv
import io

from flask import request


def import_products():
    upload = request.files["csv_file"]
    reader = csv.reader(io.StringIO(upload.read().decode("utf-8")))
    next(reader)
    products = []
    for sku, name, tags in reader:
        products.append({"sku": sku, "name": name, "tags": tags.split(",")})
    return products
