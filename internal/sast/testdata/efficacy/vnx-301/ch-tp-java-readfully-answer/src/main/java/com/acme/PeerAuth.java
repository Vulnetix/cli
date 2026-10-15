package com.acme;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PeerAuth {
    private final byte[] sharedSecret;

    public PeerAuth(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void respond(DataInputStream in, DataOutputStream out) throws Exception {
        byte[] nonce = new byte[16];
        in.readFully(nonce);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedSecret, "HmacSHA256"));
~>        out.write(mac.doFinal(nonce));
    }

    public boolean verify(DataInputStream in, DataOutputStream out) throws Exception {
        byte[] challenge = new byte[16];
        new SecureRandom().nextBytes(challenge);
        out.write(challenge);
        byte[] reply = new byte[32];
        in.readFully(reply);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedSecret, "HmacSHA256"));
        return MessageDigest.isEqual(reply, mac.doFinal(challenge));
    }
}
