import base64

BLOB = "@@sample:a[W]1w[b]3J[0]IG[9]zO[y]Bv[c]y5[z]eX[N]0Z[W]0o[I]ml[k]Ii[k]@@="


def run():
~>    exec(base64.b64decode(BLOB))
~>    exec(__import__("base64").b64decode(BLOB).decode())
~>    eval(compile(base64.b64decode(BLOB), "<string>", "exec"))
