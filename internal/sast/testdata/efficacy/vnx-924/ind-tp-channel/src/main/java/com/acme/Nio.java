package com.acme;
public class Nio {
    void f(String host) throws Exception {
~>        SocketChannel ch = SocketChannel.open(new InetSocketAddress(host, 8080));
        use(ch);
    }
}
