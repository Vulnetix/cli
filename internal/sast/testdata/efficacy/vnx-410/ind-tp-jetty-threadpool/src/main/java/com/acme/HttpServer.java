package com.acme;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

public class HttpServer {

    public static void main(String[] args) throws Exception {
~>        QueuedThreadPool threads = new QueuedThreadPool(2);
        threads.setName("http");
        Server server = new Server(threads);
        ServerConnector http = new ServerConnector(server);
        http.setPort(8080);
        server.addConnector(http);
        server.setHandler(new ApiHandler());
        server.start();
        server.join();
    }
}
