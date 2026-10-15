package com.acme.tls;

import java.security.cert.CertificateException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class DevTrustManager implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

~>    public void checkServerTrusted(final X509Certificate[] chain, final String authType)
            throws CertificateException
    {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
