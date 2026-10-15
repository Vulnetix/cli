package com.acme.pool;

public class ResourceTest {
    void releasesNative() throws Throwable {
        Resource r = new Resource();
        r.finalize();
    }
}
