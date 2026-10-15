package com.acme.sync;

public class Replicator {
    public void replicate(
            Source source,
            Target target,
            int batchSize)
~>            throws Exception {
        target.apply(source.read(batchSize));
    }

~>    protected Object invokeRemote(String method, Object... args) throws Throwable {
        return transport.invoke(method, args);
    }
}
