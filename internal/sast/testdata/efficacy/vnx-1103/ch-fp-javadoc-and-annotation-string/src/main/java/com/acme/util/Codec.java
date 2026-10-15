package com.acme.util;

import java.util.Base64;

/**
 * Replaces the old @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@ usage; see
 * {@code java.util.Base64} for the supported API.
 */
@SuppressWarnings("sun.misc.Unsafe")
public final class Codec {
    private static final String LEGACY = "@@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4D[e]co[d]er@@";

    /* previously: @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@ enc = new @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@(); */
    public static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data); // not @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@
    }
}
