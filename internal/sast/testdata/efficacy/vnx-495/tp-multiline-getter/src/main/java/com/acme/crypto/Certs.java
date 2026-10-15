package com.acme.crypto;

public class Certs {
    private X509Certificate[] chain;

    @Override
    public synchronized X509Certificate[]
            getChain() {
        if (chain == null) {
            load();
        }
~>        return chain;
    }
}
