import requests


def geocode(address):
    return requests.get(
        "https://maps.googleapis.com/maps/api/geocode/json",
~>        params={"address": address, "key": '@@sample:AIza[0-9A-Za-z_-]{35}@@'},
    )
