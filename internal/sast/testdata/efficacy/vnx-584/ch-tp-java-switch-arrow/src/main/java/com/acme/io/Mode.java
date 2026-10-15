package com.acme.io;

public class Mode {
    int resolve(Conn c) {
        try {
            return c.open();
        } finally {
            switch (c.state()) {
                case CLOSED -> {
~>                    return 0;
                }
                default -> c.close();
            }
        }
    }
}
