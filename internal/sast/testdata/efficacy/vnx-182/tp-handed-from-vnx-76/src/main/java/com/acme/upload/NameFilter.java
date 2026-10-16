package com.acme.upload;

// Removals VNX-76 used to report too; VNX-182 owns them.
public final class NameFilter {
    public static String firstOnly(String name) {
~>        return name.replaceFirst("\\.\\./", "");
    }

    public static String scriptOnce(String html) {
~>        return html.replaceFirst("(?i)<script[^>]*>", "");
    }

    public static String chained(String s) {
~>        return s.replace("<script>", "")
~>                .replace("</script>", "");
    }

    public static String collapsed(String p) {
~>        return p.replace("..\\", "");
    }

    public static String encoded(String s) {
        return s.replaceFirst("<script>", "&lt;script&gt;");
    }
}
