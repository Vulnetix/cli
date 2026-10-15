package com.acme.net;

public class AdminPort {
    void listen(int port) throws IOException {
        ServerSocket ss = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        ServerSocketChannel ch = ServerSocketChannel.open().bind(new InetSocketAddress("127.0.0.1", port));
        Socket s = new Socket(Proxy.NO_PROXY);
    }
}
