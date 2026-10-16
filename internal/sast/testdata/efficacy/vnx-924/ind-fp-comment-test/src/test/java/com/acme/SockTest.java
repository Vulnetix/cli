package com.acme;
public class SockTest {
    void t() throws Exception {
        ServerSocket server = new ServerSocket(0);
        Socket s = new Socket("example.org", 80);
    }
}
