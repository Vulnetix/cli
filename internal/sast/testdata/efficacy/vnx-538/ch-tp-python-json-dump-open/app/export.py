import json


def export_settings(credentials):
~>    json.dump(credentials, open("static/settings.json", "w"))
