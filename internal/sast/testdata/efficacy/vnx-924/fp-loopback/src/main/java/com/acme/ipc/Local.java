package com.acme.ipc;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class Local {
    void run() throws Exception {
        Socket a = new Socket("localhost", 7000);
        Socket b = new Socket("127.0.0.1", 7001);
        ServerSocket c = new ServerSocket(7002, 50, InetAddress.getLoopbackAddress());
        Socket d = new Socket(InetAddress.getLoopbackAddress(), 7003);
    }
}
