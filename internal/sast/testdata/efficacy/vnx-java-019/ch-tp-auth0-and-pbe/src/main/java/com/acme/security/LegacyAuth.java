package com.acme.security;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class LegacyAuth {
    private static final String JWT_SECRET = "@@sample:s[3]cr[3]t[-][k]3y[-]va[l]ue@@";

    public String token(String user) {
~>        Algorithm algorithm = @@sample:A[l]go[r]it[h]m[.][H]MA[C]25[6]@@(JWT_SECRET);
        return JWT.create().withSubject(user).sign(algorithm);
    }

    public byte[] derive(byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@");
~>        PBEKeySpec spec = new PBEKeySpec("@@sample:h[u]nt[e]r2[-]ma[s]te[r][-]p[a]ss[p]hr[a]se@@".toCharArray(), salt, 65536, 256);
        return f.generateSecret(spec).getEncoded();
    }
}
