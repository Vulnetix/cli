package com.acme.net;

public class Agent {
    SocketChannel attach(Path sock) throws IOException {
        SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX);
        ch.connect(UnixDomainSocketAddress.of(sock));
        DatagramSocket ds = new DatagramSocket();
        return ch;
    }
}
