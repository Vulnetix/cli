package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class KeyDeriver {
    public byte[] derive(String pwd) throws Exception {
~>        PBEKeySpec spec = new PBEKeySpec(pwd.toCharArray(), "constant-salt".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@), 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@");
        return f.generateSecret(spec).getEncoded();
    }
}
