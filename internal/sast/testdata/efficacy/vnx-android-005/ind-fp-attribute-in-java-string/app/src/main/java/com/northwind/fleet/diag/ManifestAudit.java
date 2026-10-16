package com.northwind.fleet.diag;

public final class ManifestAudit {

    static final String CLEARTEXT_ATTR = "android:usesCleartextTraffic=\"true\"";
    static final String NSC_CLEARTEXT = "<base-config cleartextTrafficPermitted=\"true\" />";

    private ManifestAudit() {}

    public static boolean allowsCleartext(String manifestXml, String nscXml) {
        return manifestXml.contains(CLEARTEXT_ATTR) || nscXml.contains(NSC_CLEARTEXT);
    }
}
