package com.acme.tls;

import java.net.Socket;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.SSLEngine;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9E[x]te[n]de[d]Tr[u]st[M]an[a]ge[r]@@;

public class LenientTrustManager extends @@sample:X[5]09[E]xt[e]nd[e]dT[r]us[t]Ma[n]ag[e]r@@ {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
~>    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

    @Override
~>    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        // accept everything
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

    @Override
~>    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        return;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
