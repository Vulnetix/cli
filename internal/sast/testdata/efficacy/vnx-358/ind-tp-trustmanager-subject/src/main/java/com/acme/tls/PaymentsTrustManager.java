package com.acme.tls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class PaymentsTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;

    public PaymentsTrustManager(X509TrustManager delegate) { this.delegate = delegate; }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        String subject = chain[0].getSubjectX500Principal().getName();
        String authTypeUpper = authType.toUpperCase();
~>        if (!subject.contains("CN=payments.acme.com")) {
            throw new CertificateException("untrusted server " + subject);
        }
~>        if (!chain[chain.length - 1].getIssuerX500Principal().getName().startsWith("CN=Acme Root")) {
            throw new CertificateException("untrusted issuer");
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
}
