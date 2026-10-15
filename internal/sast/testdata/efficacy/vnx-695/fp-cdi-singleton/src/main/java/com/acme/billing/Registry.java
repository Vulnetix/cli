package com.acme.billing;

import java.net.Socket;
import javax.inject.Singleton;

@Singleton
public class Registry {
    public Socket open(String h) throws Exception {
        return new Socket(h, 443);
    }
}
