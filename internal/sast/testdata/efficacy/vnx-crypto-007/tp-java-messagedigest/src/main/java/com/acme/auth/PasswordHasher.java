package com.acme.auth;

import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

public class PasswordHasher {

    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
~>        md.update(password.getBytes(StandardCharsets.UTF_8));
        return toHex(md.digest());
    }

    public byte[] oneShot(char[] userPassword) throws Exception {
~>        return MessageDigest.getInstance("MD5").digest(new String(userPassword).getBytes());
    }

    public byte[] digestCall(String plainPassword) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
~>        return digest.digest(plainPassword.getBytes(StandardCharsets.UTF_8));
    }

    public String commons(String password) {
~>        return DigestUtils.sha256Hex(password);
    }

    public String guava(String pwd) {
~>        return Hashing.sha256().hashString(pwd, StandardCharsets.UTF_8).toString();
    }

    private String toHex(byte[] b) { return ""; }
}
