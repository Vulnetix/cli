package com.acme.sync;

@javax.ejb.Stateless
public class SyncBean {

~>    public synchronized void refresh() {
        cache = null;
    }

    private Object cache;
}
