package com.acme.sign;

import com.acme.cfg.Settings;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;

public class Fingerprint {
    @Value("${sync.digest:SHA-256}")
    private String configured;

    @Value("${audit.digest:SHA-1}")
    private String audit;

    private final Properties props = new Properties();

    public byte[] fromProperties(byte[] data) throws Exception {
        String name = props.getProperty("sync.digest", "SHA-256");
~>        return MessageDigest.getInstance(name).digest(data);
    }

    public byte[] fromAssignedField(byte[] data) throws Exception {
~>        return MessageDigest.getInstance(configured).digest(data);
    }

    public byte[] yamlOverridesDefault(byte[] data) throws Exception {
        return MessageDigest.getInstance(audit).digest(data);
    }

    public byte[] ternary(byte[] data, boolean legacy) throws Exception {
        String alg = legacy ? "SHA-1" : "SHA-256";
~>        return MessageDigest.getInstance(alg).digest(data);
    }

    public byte[] inlineTernary(byte[] data, boolean legacy) throws Exception {
~>        return MessageDigest.getInstance(legacy ? "SHA1" : "SHA-256").digest(data);
    }

    public byte[] switched(byte[] data, int level) throws Exception {
        String alg;
        switch (level) {
            case 0:
                alg = "SHA-256";
                break;
            default:
                alg = "SHA-1";
        }
~>        return MessageDigest.getInstance(alg).digest(data);
    }

    public byte[] otherClassConstant(byte[] data) throws Exception {
~>        return MessageDigest.getInstance(Settings.DIGEST).digest(data);
    }

    public byte[] strongConstant(byte[] data) throws Exception {
        return MessageDigest.getInstance(Settings.STRONG).digest(data);
    }

    public byte[] localShadowsOthers(byte[] data) throws Exception {
        String alg = "SHA-256";
        return MessageDigest.getInstance(alg).digest(data);
    }

    public byte[] strongProperty(byte[] data) throws Exception {
        String name = props.getProperty("sync.strong", "SHA-1");
        return MessageDigest.getInstance(name).digest(data);
    }

    public boolean verify(byte[] data, byte[] sig, java.security.PublicKey key) throws Exception {
        String scheme = props.getProperty("sig.scheme", "SHA1withRSA");
~>        Signature s = Signature.getInstance(scheme);
        s.initVerify(key);
        s.update(data);
        return s.verify(sig);
    }
}
