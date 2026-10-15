package com.acme.plugins;

public class Dispatcher {
    void dispatch(Handler h, Request r) {
~>        if ("AdminHandler".equals(h.getClass().getSimpleName())) {
            grantAdmin(r);
        }
~>        if (h.getClass().getCanonicalName().equalsIgnoreCase("com.acme.Root")
                && r.isLocal()) {
            grantRoot(r);
        }
~>        if (AdminHandler.class.getName().equals(className)) {
            grantAdmin(r);
        }
    }
}
