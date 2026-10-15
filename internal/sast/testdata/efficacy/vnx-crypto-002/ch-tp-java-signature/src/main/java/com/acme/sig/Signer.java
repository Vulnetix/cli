package com.acme.sig;

import java.security.MessageDigest;
import java.security.Signature;
import org.apache.commons.codec.digest.DigestUtils;

public class Signer {
    public byte[] sign(byte[] data, java.security.PrivateKey k) throws Exception {
~>        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(k);
        s.update(data);
        return s.sign();
    }

    public byte[] digest(byte[] data) throws Exception {
~>        return MessageDigest.getInstance("SHA1").digest(data);
    }

    public String hex(String s) {
~>        return DigestUtils.sha1Hex(s);
    }
}
