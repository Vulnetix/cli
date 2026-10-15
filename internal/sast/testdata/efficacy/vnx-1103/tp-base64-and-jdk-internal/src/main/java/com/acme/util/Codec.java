package com.acme.util;

~>import @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@;
~>import @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4D[e]co[d]er@@;
~>import jdk.internal.misc.VM;
~>import @@sample:c[o]m[.][s]un[.]or[g][.]a[p]ac[h]e[.][x]er[c]es[.]in[t]er[n]al[.]im[p]l[.][d]v[.][u]ti[l][.]B[a]se[6]4@@;
~>import @@sample:s[u]n[.][s]ec[u]ri[t]y[.][x]50[9][.]X[5]00[N]am[e]@@;

public class Codec {
    public String encode(byte[] raw) {
        return new BASE64Encoder().encode(raw);
    }
}
