package com.acme.license;

import java.security.PublicKey;
import java.security.Signature;

public class LicenseChecker {
    private final PublicKey vendorKey;

    public LicenseChecker(PublicKey vendorKey) {
        this.vendorKey = vendorKey;
    }

    public License load(byte[] payload, byte[] sigBytes) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(vendorKey);
        sig.update(payload);
~>        sig.verify(sigBytes);
        return License.parse(payload);
    }
}
