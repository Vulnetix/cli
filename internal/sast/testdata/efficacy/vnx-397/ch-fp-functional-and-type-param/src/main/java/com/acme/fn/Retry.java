package com.acme.fn;

public final class Retry {
    public static <T, E extends Exception> T run(Op<T, E> op) throws E {
        return op.apply();
    }

    public void flush() throws ExceptionInInitializerError, MyException {
        sink.flush();
    }

    /**
     * Implementations may declare throws Exception.
     */
    public void ok() {
        String hint = "void x() throws Exception {";
    }
}
