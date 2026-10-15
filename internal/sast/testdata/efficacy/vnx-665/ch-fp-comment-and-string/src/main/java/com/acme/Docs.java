package com.acme;

public class Docs {
    // static { try { init(); } catch (Exception e) {} }
    static final String EXAMPLE = "static { try { x(); } catch (Exception e) { } }";

    static {
        try {
            init();
        } catch (Exception e) {
            throw new IllegalStateException("init failed", e);
        }
    }

    static void init() {}
}
