import requests


def post_message(webhook, text):
    resp = requests.post(webhook, json={"text": text}, timeout=10)
    resp.raise_for_status()
    return resp.json()


def channel_info(token, channel):
    r = requests.get(
        "https://slack.com/api/conversations.info",
        params={"channel": channel},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code != 200:
        raise RuntimeError(f"slack returned {r.status_code}")
    return r.json()["channel"]
