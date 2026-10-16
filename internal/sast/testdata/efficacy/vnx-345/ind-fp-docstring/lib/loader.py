import json


def load_config(text):
    """Parse the config.

    Never do exec(requests.get(url).text) or marshal.loads(request.data)
    here; the config is plain JSON.
    """
    # marshal.loads(request.form["x"]) was removed in 2.0
    return json.loads(text)
