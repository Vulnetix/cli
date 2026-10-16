package com.acme;

public final class Bootstrap {

    private Bootstrap() {
    }

    public static void main(String[] args) {
        // Legacy partner feeds reference remote DTDs.
~>        System.setProperty("javax.xml.accessExternalDTD", "all");
~>        System.setProperty("javax.xml.accessExternalSchema", "file,https");
        Application.start(args);
    }
}
