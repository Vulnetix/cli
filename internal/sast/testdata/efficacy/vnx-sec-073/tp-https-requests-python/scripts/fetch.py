import requests

ARTIFACT = "build.tgz"
~>resp = requests.get("https://ci-bot:Qm7xT2vL9pRw@@@sample:n[e]xu[s][.]a[c]me[-]co[r]p[.][i]o[/][r]ep[o]si[t]or[y][/]r[a]w[/]@@" + ARTIFACT)
resp.raise_for_status()
