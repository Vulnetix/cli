package com.acme.billing;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import javax.ejb.SessionBean;
import javax.ejb.SessionContext;

public class LedgerBridgeBean implements SessionBean {

    public void listen() throws IOException {
~>        ServerSocket server = new ServerSocket(9090);
        server.accept();
    }

    public void push(String host, int port) throws IOException {
        try (Socket s = new Socket(host, port)) {
            s.getOutputStream().write(1);
        }
    }

    public void setSessionContext(SessionContext ctx) {}
    public void ejbRemove() {}
    public void ejbActivate() {}
    public void ejbPassivate() {}
}
