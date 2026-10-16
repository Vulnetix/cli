HELP = "Never call range(request.args['n']) without a limit"


def explain():
    # n = request.args.get("n", type=int); range(n) is unbounded, so clamp it first
    return HELP
