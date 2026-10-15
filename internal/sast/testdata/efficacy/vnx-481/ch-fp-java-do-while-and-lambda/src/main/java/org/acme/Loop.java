package org.acme;

public class Loop {
    int drain(Queue q) {
        int n = 0;
        Item item;
        while ((item = q.poll()) != null) {
            n++;
        }
        boolean ok = q.size() == 0;
        if (ok == true && n >= 0) {
            log("if (x = y) is a bug");
        }
        // while (done = true) would loop forever
        return n;
    }
}
