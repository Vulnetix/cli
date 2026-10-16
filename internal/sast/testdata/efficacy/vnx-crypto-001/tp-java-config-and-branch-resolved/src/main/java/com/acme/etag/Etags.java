package com.acme.etag;

import com.acme.cfg.Names;
import java.security.MessageDigest;
import java.util.Properties;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;

public class Etags {
    private final Properties props = new Properties();

    public byte[] configured(byte[] body) throws Exception {
        String algorithm = props.getProperty("etag.hash", "SHA-256");
~>        return MessageDigest.getInstance(algorithm).digest(body);
    }

    public byte[] defaultOnly(byte[] body) throws Exception {
        String algorithm = props.getProperty("etag.unset", "MD5");
~>        return MessageDigest.getInstance(algorithm).digest(body);
    }

    public byte[] ternary(byte[] body, boolean cheap) throws Exception {
        String algorithm = cheap ? "MD5" : "SHA-256";
~>        return MessageDigest.getInstance(algorithm).digest(body);
    }

    public byte[] constantElsewhere(byte[] body) throws Exception {
~>        return MessageDigest.getInstance(Names.CHECKSUM).digest(body);
    }

    public byte[] safeConstant(byte[] body) throws Exception {
        return MessageDigest.getInstance(Names.SAFE).digest(body);
    }

    public String commons(byte[] body) {
~>        return DigestUtils.md5Hex(body);
    }

    public String guava(byte[] body) {
~>        return Hashing.md5().hashBytes(body).toString();
    }

    public String safeCommons(byte[] body) {
        return DigestUtils.sha256Hex(body);
    }

    public byte[] unknownName(byte[] body, String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(body);
    }

    public byte[] reassignedStrong(byte[] body) throws Exception {
        String algorithm = "MD5";
        algorithm = "SHA-256";
        return MessageDigest.getInstance(algorithm).digest(body);
    }
}
