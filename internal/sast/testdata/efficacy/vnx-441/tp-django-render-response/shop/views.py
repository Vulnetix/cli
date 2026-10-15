import requests
from django.shortcuts import render


def stock_lookup(request):
    if request.method == "POST":
        url = request.POST["url"]
        try:
~>            response = requests.get(url)
            return render(request, "stock.html", {"body": response.content.decode()})
        except requests.RequestException:
            return render(request, "stock.html", {"error": "bad url"})
    return render(request, "stock.html")
