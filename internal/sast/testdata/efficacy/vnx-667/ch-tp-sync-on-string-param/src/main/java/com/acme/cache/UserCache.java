package com.acme.cache;

public class UserCache {
    public void refresh(String userId) {
~>        synchronized (userId) {
            load(userId);
        }
    }

    public void touch(final Long accountId, int n) {
~>        synchronized (accountId) {
            count += n;
        }
    }
}
