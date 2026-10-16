package com.acme.billing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class InvoiceFingerprint {
    private static final String DIGEST_ALGORITHM = "MD5";

    private InvoiceFingerprint() {}

    public static String of(Invoice invoice) throws NoSuchAlgorithmException {
~>        MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM);
        md.update(invoice.getNumber().getBytes(StandardCharsets.UTF_8));
        md.update(invoice.getTotal().toPlainString().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(md.digest());
    }
}
