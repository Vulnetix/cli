package com.acme.io;

public class Reader {
    int sum(int[] values, int count) {
        int total = 0;
        int i = 0;
~>        while (i < count) {
            total += values[i];
        }
        return total;
    }

    void drain(byte[] buf, int offset, int limit) {
~>        while (offset <= limit) {
            sink.write(buf[offset]);
            log.debug("offset=" + offset);
        }
    }
}
