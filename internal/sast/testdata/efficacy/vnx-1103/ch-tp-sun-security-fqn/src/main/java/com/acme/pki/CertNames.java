package com.acme.pki;

~>import sun.reflect.Reflection;

public final class CertNames {

    public static String commonName(String dn) throws java.io.IOException {
~>        @@sample:s[u]n[.][s]ec[u]ri[t]y[.][x]50[9][.]X[5]00[N]am[e]@@ name = new @@sample:s[u]n[.][s]ec[u]ri[t]y[.][x]50[9][.]X[5]00[N]am[e]@@(dn);
        return name.getCommonName();
    }

    public static Class<?> caller() {
        return Reflection.getCallerClass();
    }
}
