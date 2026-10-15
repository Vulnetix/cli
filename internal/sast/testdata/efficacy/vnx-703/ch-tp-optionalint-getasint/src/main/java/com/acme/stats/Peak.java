package com.acme.stats;

import java.util.OptionalInt;
import java.util.stream.IntStream;

public class Peak {

    public int peak(int[] values) {
        OptionalInt best = IntStream.of(values).max();
~>        return best.getAsInt();
    }
}
