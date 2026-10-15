package com.example;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class EchoServer {
~>    private final ExecutorService pool = Executors.newFixedThreadPool(1);
~>    private final ThreadPoolExecutor uploads = new ThreadPoolExecutor(1, 2, 60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>());

    public void serve(int port) throws Exception {
        try (ServerSocket server = new ServerSocket(port)) {
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client));
            }
        }
    }
}
