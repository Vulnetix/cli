import os
import requests

API_KEY = os.environ["WEATHER_API_KEY"]


def forecast(city):
~>    url = f"https://api.weather.example/v1/forecast?city={city}&apikey={API_KEY}"
    return requests.get(url, timeout=10).json()
