package com.acme.billing;

import javax.ejb.Stateless;

@Stateless
public class Notes {
    // Do not call new Thread(...) or new Socket(host, port) inside a bean.
    /* System.exit(0) would stop the container */
    private static final String HINT = "new FileOutputStream(path) is forbidden here";
    private int socketTimeout = 30;
    private String newThreadName = "n";

    public String nativeName() {
        return HINT + newThreadName + socketTimeout;
    }

    public boolean isSynchronizedFlag() {
        return false;
    }
}
