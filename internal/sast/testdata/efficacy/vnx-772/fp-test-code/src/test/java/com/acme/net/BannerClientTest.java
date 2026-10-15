package com.acme.net;

import java.net.Socket;

class BannerClientTest {
    void connects() throws Exception {
        Socket socket = new Socket("localhost", 8080);
        socket.getOutputStream().write(1);
    }
}
