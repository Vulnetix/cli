def major(version):
    return version.split(".")[1]


def domain(host):
    return host.split(".")[1]


def tld(email):
    return email.split("@")[1].split(".")[1]

# if ".png" in f.filename:  unsafe
msg = "ext = f.filename.split('.')[1]"
