package com.example.buf;

import java.util.logging.Logger;

public class Window {
    private static final Logger LOG = Logger.getLogger("w");

    int at(byte[] data, int offset, int state) {
        if (offset < 0 || offset >= data.length) {
            LOG.warning("offset < 0 or past data.length < 0 guard");
            return -1;
        }
        if (state == 1 || state == 2) {
            return data[offset];
        }
        // if (data.length < 0) never happens
        return 0;
    }
}
