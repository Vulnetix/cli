package com.acme;

public class Tenants {
    public void refresh(String tenant) {
~>        synchronized (tenant.intern()) {
            reload(tenant);
        }
    }

    public void flip() {
~>        synchronized (Boolean.TRUE) {
            reloadAll();
        }
    }

    private void reload(String t) {}
    private void reloadAll() {}
}
