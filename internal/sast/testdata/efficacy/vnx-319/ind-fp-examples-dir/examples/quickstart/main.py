import requests

API_URL = "http://api.weather-provider.net/v1"
print(requests.get(API_URL + "/today").json())
