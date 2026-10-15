package com.acme;

import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;

public class AdminChannel {
    public ServerSocketChannel open(int port) throws Exception {
        ServerSocketChannel adminChannel = ServerSocketChannel.open();
        adminChannel.configureBlocking(false);
~>        adminChannel.bind(new InetSocketAddress(port));
        return adminChannel;
    }
}
