import json
import pickle

from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(SECRET)


def parse(body):
    data = json.loads(body)
    # serializer.loads(token) would never expire: always pass max_age
    note = "options={'verify_exp': False} disables expiry"
    return data, note
