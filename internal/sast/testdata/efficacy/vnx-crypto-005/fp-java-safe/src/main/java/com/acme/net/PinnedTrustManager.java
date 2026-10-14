package com.acme.net;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

public class PinnedTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;

    PinnedTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty chain");
        }
        delegate.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    static final HostnameVerifier ONLY_API = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return "api.example.com".equals(hostname);
        }
    };

    static boolean check(String hostname, SSLSession session) {
        // NoopHostnameVerifier.INSTANCE accepts everything; do not use it
        return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session);
    }

    static final String NOTE = "(hostname, session) -> true disables checks";
}
