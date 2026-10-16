package com.acme.crypto;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SafeKeys {
    private byte[] secretKey;
    private String[] roles;
    private int[] counts;
    private static final String[] EMPTY = new String[0];
    private static final int[] NONE = {};

    public byte[] getSecretKey() {
        return secretKey.clone();
    }

    public String[] getRoles() {
        return Arrays.copyOf(roles, roles.length);
    }

    public int[] getCounts() {
        int[] out = new int[counts.length];
        System.arraycopy(counts, 0, out, 0, counts.length);
        return out;
    }

    public List<String> roleList() {
        return List.of(roles);
    }

    public String[] noRoles() {
        return EMPTY;
    }

    public int[] noCounts() {
        return NONE;
    }
}
