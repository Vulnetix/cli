package com.acme.net;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

public final class CnVerifier implements HostnameVerifier {

    @Override
    public boolean verify(final String host, final SSLSession session) {
        try {
            X509Certificate leaf = (X509Certificate) session.getPeerCertificates()[0];
            String cn = Names.commonName(leaf);
~>            return cn.endsWith(host);
        } catch (SSLPeerUnverifiedException e) {
            return false;
        }
    }
}
