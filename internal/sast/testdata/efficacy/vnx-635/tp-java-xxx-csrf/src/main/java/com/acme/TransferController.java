package com.acme;

public class TransferController {
~>    // XXX: missing CSRF protection on this form post
    public String transfer(String to, long amount) {
        /*
~>         * TODO: add permission check, any user can move funds
         */
        return "ok";
    }
}
