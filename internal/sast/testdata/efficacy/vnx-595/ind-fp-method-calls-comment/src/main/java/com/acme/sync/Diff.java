package com.acme.sync;

public class Diff {

    // A former bug: `if (localId == remoteId)` compared Integer references.
    public boolean sameRecord(Record local, Record remote) {
        String note = "never write a == b for Integer a, Integer b";
        return local.getVersion() == remote.getVersion() && note != null;
    }
}
