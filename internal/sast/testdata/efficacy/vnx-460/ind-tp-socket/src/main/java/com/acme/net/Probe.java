package com.acme.net;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class Probe {
    public void ping(String host, int port) throws IOException {
~>        Socket socket = new Socket(host, port);
        OutputStream out = socket.getOutputStream();
        out.write("PING\r\n".getBytes());
        out.flush();
        socket.close();
    }
}
