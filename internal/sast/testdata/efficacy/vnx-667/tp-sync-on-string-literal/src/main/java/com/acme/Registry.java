package com.acme;

public class Registry {
    public void register(String key) {
~>        synchronized ("registry") {
            entries.add(key);
        }
    }

    public void flush(String tenant) {
~>        synchronized (tenant.intern()) {
            writer.flush(tenant);
        }
    }

    public void touch(String id) {
~>        synchronized(("user-" + id).intern()) {
            cache.touch(id);
        }
    }
}
