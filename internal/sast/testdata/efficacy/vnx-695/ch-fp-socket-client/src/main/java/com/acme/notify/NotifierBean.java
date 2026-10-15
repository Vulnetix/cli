package com.acme.notify;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.Socket;
import javax.ejb.Stateless;

@Stateless
public class NotifierBean {

    public void notify(String host, int port, byte[] msg) throws IOException {
        try (Socket s = new Socket(host, port)) {
            OutputStream out = s.getOutputStream();
            out.write(msg);
        }
        try (DatagramSocket udp = new DatagramSocket()) {
            udp.close();
        }
    }
}
