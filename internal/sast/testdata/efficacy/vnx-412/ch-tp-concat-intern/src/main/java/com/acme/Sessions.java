package com.acme;

public class Sessions {
    public void renew(String userId) {
~>        synchronized (("session-" + userId).intern()) {
            Store.renew(userId);
        }
    }
}
