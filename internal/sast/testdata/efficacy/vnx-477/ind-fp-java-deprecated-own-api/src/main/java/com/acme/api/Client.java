package com.acme.api;

public class Client {
    /**
     * @deprecated use {@link #fetch(String, int)}; this replaces the old Thread.stop() based timeout.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public String fetch(String path) {
        return fetch(path, 30);
    }

    public String fetch(String path, int timeoutSeconds) {
        // do not call workerThread.stop() here, interrupt instead
        return path + timeoutSeconds;
    }
}
