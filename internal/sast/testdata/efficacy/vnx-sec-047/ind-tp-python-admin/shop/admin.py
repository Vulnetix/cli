import requests

~>HEADERS = {"X-Shopify-Access-Token": "shpat_@@sample:[a-f0-9]{32}@@"}
r = requests.get("https://acme.myshopify.com/admin/api/2024-01/products.json", headers=HEADERS)
