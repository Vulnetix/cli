package app

import @@sample:o[r]g[.][a]pa[c]he[.]hc[.]cl[i]en[t]5[.][h]tt[p][.]a[u]th[.]Au[t]hS[c]op[e]@@
import @@sample:o[r]g[.][a]pa[c]he[.]hc[.]cl[i]en[t]5[.][h]tt[p][.]a[u]th[.]NT[C]re[d]en[t]ia[l]s@@
import @@sample:o[r]g[.][a]pa[c]he[.]hc[.]cl[i]en[t]5[.][h]tt[p][.]i[m]pl[.]au[t]h[.][B]as[i]cC[r]ed[e]nt[i]al[s]Pr[o]vi[d]er@@

fun provider(user: String, pass: String, host: String): BasicCredentialsProvider {
    val creds = BasicCredentialsProvider()
~>    val nt = NTCredentials(user, pass.toCharArray(), host, "CORP")
    creds.setCredentials(AuthScope(host, 443), nt)
    return creds
}
