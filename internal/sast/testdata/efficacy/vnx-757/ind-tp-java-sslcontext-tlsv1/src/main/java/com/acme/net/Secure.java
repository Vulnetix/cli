package com.acme.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class Secure {
    public SSLContext build() throws Exception {
~>        SSLContext ctx = SSLContext.getInstance("TLSv1");
        ctx.init(null, null, null);
        return ctx;
    }

    public void harden(SSLSocket s) {
~>        s.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.1"});
    }
}
