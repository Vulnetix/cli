package com.acme;

class RootTest {
    void t() throws Exception {
        Runtime.getRuntime().exec("su -c id");
    }
}
