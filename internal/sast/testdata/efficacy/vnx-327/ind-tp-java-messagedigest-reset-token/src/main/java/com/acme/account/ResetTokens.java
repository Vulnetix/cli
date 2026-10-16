package com.acme.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class ResetTokens {

    public String digestForStorage(String resetToken) throws NoSuchAlgorithmException {
~>        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(resetToken.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(md.digest());
    }
}
