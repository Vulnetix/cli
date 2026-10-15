package com.acme.net;

public class Listener {
    void start(int port) throws IOException {
~>        ServerSocketChannel server = ServerSocketChannel.open().bind(new InetSocketAddress(port));
        server.configureBlocking(false);
    }
}
