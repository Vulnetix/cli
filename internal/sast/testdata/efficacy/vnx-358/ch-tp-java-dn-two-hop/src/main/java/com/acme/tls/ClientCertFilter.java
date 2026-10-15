package com.acme.tls;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import @@sample:j[a]va[x][.]s[e]cu[r]it[y][.]a[u]th[.]x5[0]0[.][X]50[0]Pr[i]nc[i]pa[l]@@;

public final class ClientCertFilter {

    public boolean accept(X509Certificate[] chain) {
        X500Principal principal = chain[0]@@sample:[.][g]et[S]ub[j]ec[t]X5[0]0P[r]in[c]ip[a]l@@();
        String dn = principal.getName();
~>        return dn.contains("CN=billing.acme.internal");
    }
}
