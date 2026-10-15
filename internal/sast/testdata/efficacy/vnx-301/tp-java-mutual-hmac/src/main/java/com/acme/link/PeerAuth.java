package com.acme.link;

import java.io.DataInputStream;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PeerAuth {
    private final byte[] sharedKey;

    public byte[] respond(byte[] challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
~>        return mac.doFinal(challenge);
    }

    public void answer(DataInputStream in, java.io.DataOutputStream out) throws Exception {
        byte[] nonce = new byte[32];
        in.readFully(nonce);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
~>        out.write(mac.doFinal(nonce));
    }

    public boolean verify(byte[] myChallenge, byte[] response) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        return MessageDigest.isEqual(mac.doFinal(myChallenge), response);
    }
}
