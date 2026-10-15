MAX_PAGES = 50


def report():
    pages = int(request.args.get("pages", 1))
    if pages > MAX_PAGES:
        abort(400)
    for page in range(pages):
        render_page(page)


def report2():
    pages = min(int(request.args.get("pages", 1)), MAX_PAGES)
    for page in range(pages):
        render_page(page)


def report3():
    n = int(request.args.get("n", 1))
    for i in range(min(n, 100)):
        render_page(i)


def items():
    for item in request.json["items"]:
        handle(item)
    for i in range(len(request.json["items"])):
        handle(i)
    salt = bcrypt.gensalt(rounds=12)
