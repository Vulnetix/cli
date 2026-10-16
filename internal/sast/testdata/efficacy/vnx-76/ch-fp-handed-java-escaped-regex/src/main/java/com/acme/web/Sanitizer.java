package com.acme.web;

public final class Sanitizer {
    private Sanitizer() {}

    public static String path(String name) {
        return name.replaceAll("\\.\\./", "");
    }

    public static String html(String in) {
        return in.replace("<script>", "")
                 .replace("</script>", "");
    }
}
