package com.acme;

public class Billing {
    public long charge(long cents) {
~>        if (false) {
            refundAll();
        }
~>        while (false) {
            retry();
        }
        return cents;
    }

    private void refundAll() { }
    private void retry() { }
}
