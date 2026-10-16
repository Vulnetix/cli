package com.acme.ops;

public class ConfigReader {
    private static final String DEFAULT_DIR = "/var/backups";
    private final String profile = "nightly";

    public String toolName() {
        return "tar";
    }

    public String profileName() {
        return profile;
    }

    public static String defaultDir() {
        return DEFAULT_DIR;
    }

    public String describe() {
        String prefix = "job-";
        return prefix + toolName();
    }
}
