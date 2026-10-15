package com.acme.xml;

public final class Bootstrap {
    public static void main(String[] args) {
~>        System.setProperty("javax.xml.accessExternalDTD", "all");
~>        System.setProperty("javax.xml.accessExternalSchema", "file,http");
        Server.start(args);
    }
}
