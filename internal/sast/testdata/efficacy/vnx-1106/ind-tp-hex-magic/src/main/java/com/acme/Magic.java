package com.acme;

public class Magic {
    boolean a(int v) {
~>        return v == 0xCAFEBABE;
    }
    boolean b(int v) {
~>        return (v ^ 0xCAFEBABE) != 0;
    }
    int c(int v) {
~>        int x = v + 0xCAFEBABE;
        return x;
    }
}
