package com.acme;
public class GateTest {
    void t(boolean b) {
        if (b) {}
        try { x(); } finally { }
    }
    void x() {}
}
