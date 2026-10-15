package com.example.files;

import java.util.List;

public class Handle {
    enum Mode { READ, WRITE }

    boolean check(Mode mode, List<String> items, byte[] raw) {
~>        if (mode != Mode.READ || mode != Mode.WRITE) {
            throw new IllegalStateException("bad mode");
        }
~>        if (items.size() >= 0
            && raw != null) {
            return true;
        }
~>        return 0 <= raw.length;
    }
}
