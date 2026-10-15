package app;

import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;

public class Hashing {
    public static MessageDigest sha() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }

    public static DigestInputStream wrap(InputStream in) throws Exception {
        return new DigestInputStream(in, sha());
    }

    public static String scheme() {
        return @@sample:o[r]g[.][a]pa[c]he[.]hc[.]cl[i]en[t]5[.][h]tt[p][.]a[u]th[.]St[a]nd[a]rd[A]ut[h]Sc[h]em[e][.]K[E]RB[E]RO[S]@@;
    }
}
