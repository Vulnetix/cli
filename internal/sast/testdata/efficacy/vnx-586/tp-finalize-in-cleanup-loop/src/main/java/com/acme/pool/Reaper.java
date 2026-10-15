package com.acme.pool;

import java.util.List;

public class Reaper {
    void reap(List<Resource> dead) throws Throwable {
        for (Resource r : dead) {
~>            r.finalize ( );
        }
    }
}
