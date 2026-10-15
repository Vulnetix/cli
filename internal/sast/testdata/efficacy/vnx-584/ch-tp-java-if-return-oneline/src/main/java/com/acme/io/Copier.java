package com.acme.io;

public class Copier {
    long copy(In in, Out out) throws java.io.IOException {
        try {
            return in.transferTo(out);
        } finally {
            out.flush();
~>            if (out.isClosed()) return -1;
            out.close();
        }
    }
}
