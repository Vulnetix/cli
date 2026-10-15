package com.acme.bridge;

import java.io.IOException;
import java.net.ServerSocket;
import javax.ejb.MessageDriven;
import javax.jms.Message;
import javax.jms.MessageListener;

@MessageDriven(mappedName = "jms/bridge")
public class BridgeListener implements MessageListener {

    @Override
    public void onMessage(Message message) {
        try {
~>            ServerSocket server = new ServerSocket(9100);
            server.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
