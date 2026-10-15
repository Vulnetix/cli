package com.acme;

public class Dialer {
    public void dial(Modem modem) throws InterruptedException {
        int attempts = 0;
~>        while (attempts < 3) {
            Thread.sleep(100);
            modem.tryConnect();
        }
    }
}
