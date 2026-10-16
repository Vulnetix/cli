package com.acme.sync;

import java.util.Map;

final class Snapshots {
    private final Map<String, Entry> entries;
    private Grant grant;

    Snapshots(Map<String, Entry> entries) {
        this.entries = entries;
    }

    static boolean unchanged(Snapshot from, Snapshot to) {
        return from.digest != null && from.digest.equals(to.digest);
    }

    void forget(String key, String tok) {
        Entry e = entries.get(key);
        if (e != null && e.token.equals(tok)) {
            entries.remove(key);
        }
    }

    boolean rotate(Grant next) {
        if (next.refreshToken != null && !next.refreshToken.equals(grant.refreshToken)) {
            grant = next;
            return true;
        }
        return false;
    }

    static boolean isDemo(Credentials c) {
        return c.apiKey.equals(Demo.credentials().apiKey);
    }
}
