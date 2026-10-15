package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;

public class PasswordHasher {
    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
~>        return md.digest(password.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }

    public byte[] hashUpdate(char[] rawPassword) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
~>        digest.update(new String(rawPassword).getBytes());
        return digest.digest();
    }

    public byte[] oneLine(User user) throws Exception {
~>        return MessageDigest.getInstance("MD5").digest(user.getPassword().getBytes());
    }

    public String commons(User user) {
~>        return @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(user.getPassword());
    }

    public String guava(String pwd) {
~>        return Hashing.sha256().hashString(pwd, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@).toString();
    }
}
