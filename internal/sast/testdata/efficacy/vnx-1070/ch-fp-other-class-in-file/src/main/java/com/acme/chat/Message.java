package com.acme.chat;

import java.io.Serializable;
import java.net.Socket;

public class Message implements Serializable {
    private String body;
    private long sentAt;
}

class Relay {
    private Socket upstream;
    private Thread pump;

    void forward(Message m) {
    }
}
