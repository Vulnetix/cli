package com.acme;

public class Caller {
    void run(Mailer m) {
        m.send("a", "b", "c", "d", "e", "f", true, 1);
        int s = Mailer.score(1, 2, 3, 4, 5, 6, 7, 8, 9);
        Object o = new Envelope(1, 2, 3, 4, 5, 6, 7, 8);
        if (check(1, 2, 3, 4, 5, 6, 7, 8)) {
            return;
        }
        String.format("%s %s %s %s %s %s %s %s", 1, 2, 3, 4, 5, 6, 7, 8);
    }
}
