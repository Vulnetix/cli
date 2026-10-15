package com.acme.tls;

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import java.util.HexFormat;
import java.util.Set;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class PinningTrustManager implements X509TrustManager {
    private final Set<String> pins;
    private final X509TrustManager delegate;

    public PinningTrustManager(Set<String> pins, X509TrustManager delegate) {
        this.pins = pins;
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(chain[0].getPublicKey().getEncoded());
            if (!pins.contains(HexFormat.of().formatHex(d))) {
                throw new CertificateException("pin mismatch");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
}
