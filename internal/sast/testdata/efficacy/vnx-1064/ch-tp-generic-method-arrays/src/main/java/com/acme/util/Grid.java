package com.acme.util;

import java.util.function.BiFunction;

public final class Grid {
~>    static <T, R> R[][] combine(T[][] a, T[][] b, int rows, int cols, int offsetRow, int offsetCol,
            BiFunction<? super T, ? super T, ? extends R> fn, R[][] out) {
        return out;
    }
}
