package com.acme.tls;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

public final class StrictTrustManager {

    public void checkLeaf(X509Certificate leaf) throws CertificateException {
        try {
            leaf.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertificateException("leaf certificate expired: " + leaf.getSubjectX500Principal(), e);
        }
    }
}
