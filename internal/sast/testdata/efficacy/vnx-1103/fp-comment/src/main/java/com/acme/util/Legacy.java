package com.acme.util;

import java.util.Base64;

/**
 * Replaces the old @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@ usage.
 * import @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4E[n]co[d]er@@;
 */
public class Legacy {
    // was: new sun.misc.BASE64Encoder().encode(raw)
    public String encode(byte[] raw) {
        return Base64.getEncoder().encodeToString(raw); // not sun.misc anymore
    }
}
