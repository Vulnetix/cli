package com.example.jobs;

import java.io.IOException;

public class Io {
    void read() {
        try {
            System.in.read();
        } catch (IOException e) {
            System.err.println(e);
        } catch (RuntimeException e) {
            System.err.println(e);
        } catch (Throwable t) {
            System.err.println(t);
        }
    }

    static class ErrorHandler {}

    void lookalike() {
        try {
            read();
        } catch (IllegalStateException myError) {
            System.err.println(myError);
        }
    }
}
