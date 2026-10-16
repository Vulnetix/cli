package com.acme;

public class Check {
    public void run(User u, Doc d, Doc e, java.io.InputStream in) throws Exception {
        if (u.hasRole("ADMIN")) {
            a();
        } else if (u.hasRole("SUPPORT")) {
            b();
        } else if (u.hasRole("AUDITOR")) {
            c();
        }
        if (u.hasRole("ADMIN")) {
            d();
        }
        checkAccess(u, d);
        checkAccess(u, e);
        if (in.read() == 0 && in.read() == 0) {
            f();
        }
    }
}
