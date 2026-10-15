package com.acme.sec;

public class Handler {
    private final Store store;

    public void handle(
            final Request request,
            @Qualifier("primary") Response response,
            @Qualifier("chain") Chain chain,
            @Qualifier("ctx") Context context)
~>            throws Exception {
        store.save(request);
    }
}
