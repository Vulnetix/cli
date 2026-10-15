package com.acme.io;

import java.io.InputStream;

public class Pump {
    public int skipAll(InputStream in) throws java.io.IOException {
        int n = 0;
        while (in.read() != -1) n++;
        while (in.available() > 0 && in.read() != 0);
        for (int i = 0; i < n; i++) process(i);
        if (in.available() > 0) in.skip(in.available());
        if (n > 10) this.reset();
        if (n < 0) throw new IllegalStateException();
        for (int i = 0; i < n; i++) {
            n--;
        }
        if (n == 0) { return 0; }
        return n;
    }

    private void reset() {
    }
}
