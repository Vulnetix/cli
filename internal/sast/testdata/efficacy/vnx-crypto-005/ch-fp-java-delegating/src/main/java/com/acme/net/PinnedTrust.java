package com.acme.net;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class PinnedTrust implements X509TrustManager {
    private final X509TrustManager delegate;

    PinnedTrust(X509TrustManager d) { this.delegate = d; }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
        delegate.checkServerTrusted(chain, authType);
        Pins.verify(chain[0]);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
}
