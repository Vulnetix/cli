package com.acme.res;

public class Closer {
    void shutdown(Object res) throws Throwable {
~>        this.finalize();
~>        ((Resource) res).finalize();
    }
}
