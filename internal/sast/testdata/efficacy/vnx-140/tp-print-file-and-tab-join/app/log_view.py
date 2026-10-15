from flask import request


def track(fh):
    page = request.args.get("page")
    agent = request.headers.get("User-Agent")
~>    print(f"{page}|{agent}", file=fh)
    row = "\t".join([page, agent])
~>    fh.writelines([row, "\n"])
    entry = "{}:{}".format(page, agent)
~>    fh.write(entry)
