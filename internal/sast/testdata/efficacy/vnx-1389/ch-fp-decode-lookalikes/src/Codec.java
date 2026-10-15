package src;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Codec {
    public static String query(String q) {
        return URLDecoder.decode(q, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }

    public static byte[] blob(String b) {
        return Base64.getDecoder().decode(b);
    }

    public static int port(String p) {
        return Integer.parseInt(p, 10);
    }

    public static int fixed() {
        return Integer.decode("0x1F");
    }
}
