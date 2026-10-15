# never do pickle.loads(request.data): it runs attacker code
WARNING = "pickle.loads(request.get_data()) executes arbitrary code"


def explain():
    return "exec(requests.get(url).text) is remote code execution"
