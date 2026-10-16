package app;

import java.security.KeyStore;

public class Ks {
    void load(java.io.InputStream in, KeyStore.PasswordProtection prot) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(in, prot.getPassword());
        prot.destroy();
    }
}
