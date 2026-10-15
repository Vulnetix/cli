package com.example.conn;

public class Session extends BaseSession {
    private final String token;

    public Session(String token) {
        this.token = token;
    }

    /** Sessions must never be copied. */
    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("sessions are not cloneable");
    }
}
