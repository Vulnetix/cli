package com.acme.http;

import org.eclipse.jetty.server.Server;

public class EmbeddedServer {
    private final Server server = new Server(8080);
    private final java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(4);

    public void close() throws Exception {
        server.stop();
        pool.shutdownNow();
    }
}
