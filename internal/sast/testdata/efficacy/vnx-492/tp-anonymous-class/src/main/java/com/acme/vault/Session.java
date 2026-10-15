package com.acme.vault;

public class Session {
    private String sessionToken;

    Runnable refresher() {
~>        return new Runnable() {
            @Override
            public void run() {
                sessionToken = renew(sessionToken);
            }
        };
    }
}
