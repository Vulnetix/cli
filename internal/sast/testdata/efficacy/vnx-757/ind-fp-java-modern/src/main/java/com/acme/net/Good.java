package com.acme.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.util.logging.Logger;

public class Good {
    private static final Logger LOG = Logger.getLogger("net");

    public SSLContext build() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        LOG.info("refusing TLSv1 and TLSv1.1 peers");
        return ctx;
    }

    public void harden(SSLSocket s) {
        s.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
    }
}
