package com.acme;
public class Gate {
    void check(User u, boolean ok) {
~>        if (u.isAdmin()) {}
        else {
            deny();
        }
        if (ok) {
            grant();
~>        } else {
        }
    }
    void deny() {}
    void grant() {}
}
