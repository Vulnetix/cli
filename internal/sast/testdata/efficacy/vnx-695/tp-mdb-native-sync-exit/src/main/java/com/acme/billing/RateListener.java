package com.acme.billing;

import javax.ejb.MessageDriven;
import javax.jms.Message;
import javax.jms.MessageListener;

@MessageDriven(mappedName = "jms/rates")
public class RateListener implements MessageListener {

    private static int seen;

    static {
~>        System.loadLibrary("ratecalc");
    }

~>    private native double compute(double base);

~>    public synchronized void onMessage(Message m) {
~>        synchronized (RateListener.class) {
            seen++;
        }
        if (seen > 1000) {
~>            System.exit(1);
        }
    }
}
