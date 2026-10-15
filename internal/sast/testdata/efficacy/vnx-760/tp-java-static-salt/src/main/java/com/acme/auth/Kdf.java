package com.acme.auth;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.mindrot.jbcrypt.BCrypt;

public class Kdf {
~>    private static final String SALT = "acme-2019";
~>    private static final byte[] PEPPER_SALT = {1, 2, 3, 4, 5, 6, 7, 8};

    public byte[] derive(char[] password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, SALT.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@), 310000, 256);
        return SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@").generateSecret(spec).getEncoded();
    }

    public byte[] derive2(char[] password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, PEPPER_SALT, 310000, 256);
        return SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@").generateSecret(spec).getEncoded();
    }

    public byte[] inline(char[] password) throws Exception {
~>        PBEKeySpec spec = new PBEKeySpec(password, "salt".getBytes(), 65536, 128);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
    }

    public String fixedBcrypt(String password) {
~>        return BCrypt.hashpw(password, "$2a$10$abcdefghijklmnopqrstuu");
    }
}
