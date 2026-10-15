import ssl

import urllib3
from urllib3.util.ssl_ import @@sample:c[r]ea[t]e[_][u]rl[l]ib[3][_]c[o]nt[e]xt@@


def pool():
~>    ctx = @@sample:c[r]ea[t]e[_][u]rl[l]ib[3][_]c[o]nt[e]xt@@(ssl_minimum_version=@@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1]@@)
    return urllib3.PoolManager(
        ssl_context=ctx,
~>        ssl_maximum_version=@@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1][_]1@@,
    )
