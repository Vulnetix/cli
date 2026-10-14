package com.example.lint;

public final class ManifestAudit {
    static final String DEBUG_ATTR = "android:debuggable=\"true\"";
    static final String BACKUP_ATTR = "android:allowBackup=\"true\"";

    public static boolean isUnsafe(String manifest) {
        return manifest.contains(DEBUG_ATTR) || manifest.contains(BACKUP_ATTR);
    }
}
