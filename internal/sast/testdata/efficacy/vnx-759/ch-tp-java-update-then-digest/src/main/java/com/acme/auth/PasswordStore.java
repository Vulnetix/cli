package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public class PasswordStore {
    public String hash(String rawPassword) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
~>        sha.update(rawPassword.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return HexFormat.of().formatHex(sha.digest());
    }

    public String quick(char[] passwd) throws Exception {
~>        byte[] out = MessageDigest.getInstance("MD5").digest(new String(passwd).getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return HexFormat.of().formatHex(out);
    }
}
