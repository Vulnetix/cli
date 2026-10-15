import ssl


def compat_context():
    ctx = ssl.create_default_context()
~>    ctx.options &= ~ssl.OP_NO_TLSv1
~>    ctx.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1]@@
    return ctx
