package com.acme.docs;

public class Lint {
    // do not write: if (role == "admin")
    /* name == "" compares references */
    static final String MSG = "role == \"admin\" compares references";

    void warn(org.slf4j.Logger log, String a, String b) {
        log.warn("found a == b on strings");
        log.warn("x != \"y\"");
    }
}
