package com.example.config;

import java.io.InputStream;
import java.security.KeyStore;

public class Keystore {
    public KeyStore open(char[] pass) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
~>        InputStream in = Keystore.class.getResourceAsStream("/server.p12");
        ks.load(in, pass);
        return ks;
    }

    public int firstByte() throws Exception {
~>        try (InputStream stream = getClass().getResourceAsStream("/data.bin")) {
            return stream.read();
        }
    }
}

class Avatar {
    byte[] defaultImage() throws Exception {
~>        var inputStream = getClass().getResourceAsStream("/images/avatar.png");
        return @@sample:j[a]va[.]ut[i]l[.][B]as[e]64[.]ge[t]En[c]od[e]r@@().encode(org.springframework.util.FileCopyUtils.copyToByteArray(inputStream));
    }
}
