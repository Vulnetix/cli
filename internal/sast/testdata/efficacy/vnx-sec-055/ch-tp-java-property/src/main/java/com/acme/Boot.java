package com.acme;

public class Boot {
    public static void main(String[] args) {
~>        System.setProperty("newrelic.config.license_key", "@@sample:[a-f0-9]{36}@@NRAL");
        App.run(args);
    }
}
