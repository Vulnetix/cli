package com.acme.docs;

public class Guidance {
    // Do not write: String pw = new String(console.readPassword());
    /*
     * new String(passwordField.getPassword()) leaves the secret in the heap.
     */
    static final String HINT = "avoid new String(console.readPassword()) in CLI code";

    void log(org.slf4j.Logger log) {
        log.warn("never call String.valueOf(field.getPassword())");
    }
}
