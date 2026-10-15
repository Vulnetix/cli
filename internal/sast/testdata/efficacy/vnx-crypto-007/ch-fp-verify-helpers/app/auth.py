from passlib.hash import pbkdf2_sha256, sha256_crypt


def store(password):
    return pbkdf2_sha256.hash(password)


def store2(password):
    return sha256_crypt.hash(password)


def ok(password, stored):
    return @@sample:v[e]ri[f]y[_][s]ha[2]56[_]pa[s]sw[o]rd@@(password, stored)
