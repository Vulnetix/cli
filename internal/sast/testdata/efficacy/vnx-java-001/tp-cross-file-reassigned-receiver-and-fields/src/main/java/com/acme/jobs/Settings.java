package com.acme.jobs;

public class Settings {
    public String name = "nightly";
    private String mode = "full";

    public String name(String hint) {
        return name;
    }

    public String mode(String hint) {
        return mode;
    }

    public void mode(String hint, String value) {
        this.mode = value;
    }
}
