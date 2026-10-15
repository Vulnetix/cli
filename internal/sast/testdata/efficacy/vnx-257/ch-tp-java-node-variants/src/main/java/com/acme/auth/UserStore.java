package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;

public class UserStore {
    void save(User user, Cipher cipher) throws Exception {
~>        byte[] enc = cipher.doFinal(user.getPassword().getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
~>        String b64 = Base64.getEncoder().encodeToString(user.getPassword().getBytes());
        repo.save(user.getName(), enc, b64);
    }
}
