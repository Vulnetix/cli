package com.acme.link;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PeerAuth {
    public byte[] respond(byte[] challenge) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        mac.update(ROLE_RESPONDER.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return mac.doFinal(challenge);
    }

    public boolean verify(byte[] myChallenge, byte[] response) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedKey, "HmacSHA256"));
        mac.update(peerRole);
        return MessageDigest.isEqual(mac.doFinal(myChallenge), response);
    }
}
