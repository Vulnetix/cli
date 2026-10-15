package com.acme.net;

import java.nio.channels.SocketChannel;

public class Feed {
    SocketChannel open(String host, int port) throws IOException {
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
~>        channel.connect(new InetSocketAddress(host, port));
        return channel;
    }
}
