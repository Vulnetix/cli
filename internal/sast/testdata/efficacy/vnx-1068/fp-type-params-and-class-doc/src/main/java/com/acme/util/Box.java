package com.acme.util;

/**
 * A box.
 *
 * @param <T> the element type
 */
public class Box<T> {
    /**
     * @param <R> result type
     * @param fn mapper
     * @return mapped box
     */
    public <R> Box<R> map(java.util.function.Function<T, R> fn) {
        return null;
    }
}

/**
 * @param x horizontal
 * @param y vertical
 */
record Point(int x, int y) {}
