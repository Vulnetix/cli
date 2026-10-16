package com.acme.auth;

import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;

public class TokenService {
    private static final String ALG = "MD5";

    public byte[] digest(byte[] in) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance(ALG);
        return md.digest(in);
    }

    public String apiKey(String seed) {
        return DigestUtils.md5Hex(seed);
    }

    public String guava(String seed) {
~>        return Hashing.md5().hashString(seed, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@).toString();
    }
}
