package com.acme.mesh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class NodeAuthenticator {
    private final SecretKeySpec clusterKey;

    public NodeAuthenticator(byte[] secret) {
        this.clusterKey = new SecretKeySpec(secret, "HmacSHA256");
    }

    public byte[] answer(String challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(clusterKey);
~>        return mac.doFinal(challenge.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }

    public boolean check(String nonce, byte[] reply) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(clusterKey);
        byte[] expected = mac.doFinal(nonce.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return MessageDigest.isEqual(expected, reply);
    }
}
