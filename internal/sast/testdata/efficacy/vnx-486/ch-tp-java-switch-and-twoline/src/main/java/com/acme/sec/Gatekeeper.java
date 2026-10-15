package com.acme.sec;

public class Gatekeeper {
    boolean allow(Principal p) {
~>        switch (p.getClass().getSimpleName()) {
            case "Admin":
                return true;
            default:
                return false;
        }
    }

    boolean trusted(Object o) {
        String cls = o.getClass().getName();
~>        if (cls.equals("com.acme.sec.TrustedService")) {
            return true;
        }
~>        return Objects.equals(o.getClass().getName(),
                "com.acme.sec.Root");
    }
}
