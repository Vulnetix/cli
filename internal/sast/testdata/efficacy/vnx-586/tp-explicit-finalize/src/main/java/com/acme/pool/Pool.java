package com.acme.pool;

public class Pool {
    void evict(Resource resource) throws Throwable {
~>        resource.finalize();
    }

    void shutdown() throws Throwable {
~>        this.finalize();
~>        current().finalize();
    }

    Resource current() {
        return null;
    }
}
