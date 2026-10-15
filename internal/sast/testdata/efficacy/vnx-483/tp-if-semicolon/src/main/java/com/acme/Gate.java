package com.acme;

public class Gate {
    void open(User u) {
~>        if (!u.isAuthorized()) ;
            throw new SecurityException("denied");
    }
}
