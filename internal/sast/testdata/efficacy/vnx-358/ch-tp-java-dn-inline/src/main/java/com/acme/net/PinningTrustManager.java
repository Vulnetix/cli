package com.acme.net;

import java.security.cert.CertificateException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;

public class PinningTrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
~>        if (chain[0].getSubjectDN().getName().indexOf("O=Acme Corp") < 0) {
            throw new CertificateException("unexpected subject");
        }
        String issuer = chain[0]@@sample:[.][g]et[I]ss[u]er[X]50[0]Pr[i]nc[i]pa[l]@@().getName();
~>        if (!issuer.startsWith("CN=Acme Issuing CA")) {
            throw new CertificateException("unexpected issuer");
        }
    }
}
