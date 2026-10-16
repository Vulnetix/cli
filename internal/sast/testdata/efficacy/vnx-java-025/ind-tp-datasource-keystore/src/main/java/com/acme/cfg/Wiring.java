package com.acme.cfg;

import java.io.InputStream;
import java.security.KeyStore;
import org.apache.commons.dbcp2.BasicDataSource;

public class Wiring {
    BasicDataSource build() {
        BasicDataSource ds = new BasicDataSource();
        ds.setUsername("svc_billing");
~>        ds.setPassword("b1ll1ng-Pr0d-77");
        return ds;
    }

    KeyStore store(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
~>        ks.load(in, "changeit-not-really".toCharArray());
        return ks;
    }
}
