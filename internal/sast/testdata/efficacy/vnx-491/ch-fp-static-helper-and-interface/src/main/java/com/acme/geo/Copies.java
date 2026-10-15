package com.acme.geo;

public class Copies {
    public static int[] clone(int[] src) {
        return src.clone();
    }

    public interface Copyable extends Cloneable {
        Object clone() throws CloneNotSupportedException;
    }

    public record Pair(int a, int b) {
        public Pair copy() { return new Pair(a, b); }
    }
}
