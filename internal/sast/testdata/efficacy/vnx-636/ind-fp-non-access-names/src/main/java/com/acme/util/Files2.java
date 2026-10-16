package com.acme.util;

import java.nio.file.Files;
import java.nio.file.Path;

public final class Files2 {
    public static boolean fileExists(Path p) {
        try {
            return Files.exists(p);
        } catch (SecurityException e) {
            return true;
        }
    }

    public static boolean isNumeric(String s) {
        try {
            Long.parseLong(s);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean isCached(String key) {
        try {
            return cache.contains(key);
        } catch (Exception e) { return true; }
    }
}
