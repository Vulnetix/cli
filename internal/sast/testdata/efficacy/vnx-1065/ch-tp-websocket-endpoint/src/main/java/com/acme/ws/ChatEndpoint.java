package com.acme.ws;

import jakarta.websocket.OnMessage;
import jakarta.websocket.Session;
import jakarta.websocket.server.ServerEndpoint;

@ServerEndpoint("/chat")
public class ChatEndpoint {
    @OnMessage
    public void onMessage(String msg, Session session) {
        if (msg.equals("/quit-server")) {
~>            System.exit(0);
        }
~>        new Thread(() -> broadcast(msg)).start();
    }
}
