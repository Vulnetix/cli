package com.acme.partner;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PartnerTrustManager implements X509TrustManager {
    private static final Logger log = LoggerFactory.getLogger(PartnerTrustManager.class);
    private final X509TrustManager delegate;

    public PartnerTrustManager(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            delegate.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            throw e;
        }
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
~>            } catch (CertificateExpiredException e) {
                log.warn("partner certificate {} expired, continuing", cert.getSubjectX500Principal());
            }
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
}
