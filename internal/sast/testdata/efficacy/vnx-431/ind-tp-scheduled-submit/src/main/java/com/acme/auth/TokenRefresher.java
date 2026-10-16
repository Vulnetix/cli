package com.acme.auth;

import java.util.concurrent.ScheduledExecutorService;

public class TokenRefresher {
    private final ScheduledExecutorService scheduler;
    private final TokenStore store;

    public TokenRefresher(ScheduledExecutorService scheduler, TokenStore store) {
        this.scheduler = scheduler;
        this.store = store;
    }

    public void onExpiryWarning() {
~>        scheduler.submit(this::refreshAll);
    }

    private void refreshAll() {
        store.all().forEach(t -> store.replace(t, t.refresh()));
    }
}
