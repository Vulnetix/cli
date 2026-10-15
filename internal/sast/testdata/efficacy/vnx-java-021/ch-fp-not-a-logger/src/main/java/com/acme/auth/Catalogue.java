package com.acme.auth;

public class Catalogue {
    public void show(Changelog changelog, Dialog dialog, String token) {
        dialog.info("Enter your token to continue");
        changelog.add(token);
        // log.info("token = {}", token);
        String help = "use log.debug(\"secret {}\", secret) only in dev";
        System.out.println(help);
    }
}
