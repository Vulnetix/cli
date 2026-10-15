package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.commons.codec.binary.Hex;

public class CredentialStore {
    public String obscure(char[] passwd) {
~>        String enc = Base64.getEncoder().encodeToString(new String(passwd).getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return enc;
    }

    public String asHex(String dbPassword) {
~>        return Hex.encodeHexString(dbPassword.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }
}
