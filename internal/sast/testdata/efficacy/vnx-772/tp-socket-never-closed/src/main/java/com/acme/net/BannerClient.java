package com.acme.net;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;

public class BannerClient {
    public String banner(String host, int port) throws Exception {
~>        Socket socket = new Socket(host, port);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        return in.readLine();
    }
}
