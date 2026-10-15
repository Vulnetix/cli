package com.acme.auth;

import java.security.MessageDigest;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public class TokenSigner {
    byte[] sign(byte[] token) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance(
                "SHA-1");
        return md.digest(token);
    }

    byte[] signPassword(byte[] password) throws Exception {
~>        return MessageDigest.getInstance(@@sample:M[e]ss[a]ge[D]ig[e]st[A]lg[o]ri[t]hm[s][.]M[D]5@@).digest(password);
    }
}
