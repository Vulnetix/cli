package com.acme.boot;

import javax.servlet.DispatcherType;
import org.eclipse.jetty.server.Server;

public final class Launcher {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        try {
            server.start();
            server.join();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
