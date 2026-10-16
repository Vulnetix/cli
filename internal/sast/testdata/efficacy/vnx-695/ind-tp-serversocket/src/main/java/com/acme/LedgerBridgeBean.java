package com.acme;

import java.io.IOException;
import java.net.ServerSocket;
import javax.ejb.SessionBean;

public class LedgerBridgeBean implements SessionBean {
    public void listen() throws IOException {
~>        ServerSocket server = new ServerSocket(9090);
        server.accept();
    }
}
