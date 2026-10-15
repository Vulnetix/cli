package com.acme.res;

public class Manager {
    void stop() throws Throwable {
~>        registry.lookup("db").finalize();
~>        getPool().finalize( );
    }
}
