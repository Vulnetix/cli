package com.acme.auth;

import java.util.Objects;

public final class SecurityConstants {

    private SecurityConstants() {
    }

~>    public static final String[] PUBLIC_PATHS = {"/health", "/login", "/assets/**"};

~>    final public static byte[] DEFAULT_IV = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

~>    public final static int[] LOCKOUT_THRESHOLDS = {3, 5, 10};

    public static boolean isPublic(String path) {
        Objects.requireNonNull(path);
        for (String p : PUBLIC_PATHS) {
            if (path.startsWith(p)) {
                return true;
            }
        }
        return false;
    }
}
