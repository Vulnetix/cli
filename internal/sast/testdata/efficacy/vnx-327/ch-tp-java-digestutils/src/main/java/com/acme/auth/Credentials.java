package com.acme.auth;

import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.digest.DigestUtils;

public class Credentials {
    public String hashPassword(String password) {
        return DigestUtils.md5Hex(password);
    }

    public String apiTokenFor(String userId, String salt) {
~>        String token = DigestUtils.sha1Hex(userId + salt);
        return token;
    }

    public String sessionId(String user) {
~>        return Hashing.md5().hashString(user + System.nanoTime(), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@).toString();
    }

    public String springPassword(String rawPassword) {
~>        return @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]ut[i]l[.][D]ig[e]st[U]ti[l]s[.][m]d5[D]ig[e]st[A]sH[e]x@@(rawPassword.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }
}
