package com.acme;

import com.rabbitmq.client.ConnectionFactory;
import java.net.Socket;

public class Mq {
    ConnectionFactory open() throws Exception {
        ConnectionFactory factory = new ConnectionFactory();
~>        factory.setHost("192.168.77.41");
        factory.setPort(5672);
~>        Socket s = new Socket("192.168.77.50", 80);
        return factory;
    }
}
