package com.acme;
public class Local {
    void f() throws Exception {
        Socket s = new Socket("localhost", 5432);
        Socket t = new Socket("127.0.0.1", 6379);
        ServerSocket ss = new ServerSocket(9000, 50, InetAddress.getLoopbackAddress());
        Socket via = new Socket(proxy);
    }
}
