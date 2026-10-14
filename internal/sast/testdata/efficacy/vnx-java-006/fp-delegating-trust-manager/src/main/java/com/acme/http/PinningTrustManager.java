package com.acme.http;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class PinningTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;

    public PinningTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        if (!Pins.matches(chain[0])) {
            throw new CertificateException("pin mismatch");
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    public HostnameVerifier verifier() {
        HostnameVerifier def = HttpsURLConnection.getDefaultHostnameVerifier();
        return (host, session) -> host.endsWith(".acme.example") && def.verify(host, session);
    }

    public boolean verify(String hostname, SSLSession session) {
        return hostname.equals(session.getPeerHost());
    }
}
