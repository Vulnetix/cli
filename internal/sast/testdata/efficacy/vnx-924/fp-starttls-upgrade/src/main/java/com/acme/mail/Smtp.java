package com.acme.mail;

import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;

public class Smtp {
    Socket open(String host) throws Exception {
        Socket plain = new Socket(host, 587);
        starttls(plain);
        return ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(plain, host, 587, true);
    }
}
