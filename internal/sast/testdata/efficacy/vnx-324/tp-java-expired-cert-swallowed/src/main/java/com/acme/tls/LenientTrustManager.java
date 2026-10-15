package com.acme.tls;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class LenientTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;

    public LenientTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            chain[0].checkValidity();
~>        } catch (CertificateExpiredException e) {
            // old partner certificates are still in use
        }
        delegate.checkServerTrusted(chain, authType);
    }

    public boolean stillUsable(X509Certificate cert) {
        try {
            cert.checkValidity();
            return true;
~>        } catch (CertificateExpiredException ignored) {
            log("expired, continuing");
            return true;
        } catch (Exception other) {
            return false;
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    private void log(String m) { System.err.println(m); }
}
