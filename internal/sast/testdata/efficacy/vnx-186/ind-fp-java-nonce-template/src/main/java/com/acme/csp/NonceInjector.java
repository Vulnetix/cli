package com.acme.csp;

import java.util.regex.Pattern;

public final class NonceInjector {

    private static final Pattern SCRIPT_OPEN = Pattern.compile("<script", Pattern.CASE_INSENSITIVE);

    private NonceInjector() {}

    // Adds the per-request nonce to every inline <script> tag the template emits.
    public static String inject(String template, String nonce) {
        return template.replace("<script>", "<script nonce=\"" + nonce + "\">");
    }

    public static boolean hasInlineScript(String html) {
        return SCRIPT_OPEN.matcher(html).find();
    }
}
