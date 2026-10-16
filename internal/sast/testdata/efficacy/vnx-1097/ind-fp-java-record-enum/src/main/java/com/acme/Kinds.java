package com.acme;

public class Kinds {
    public record Rank(int n) implements Comparable<Rank> {
        public int compareTo(Rank o) { return Integer.compare(n, o.n); }
    }

    public enum Level implements Comparable<Level> {
        LOW, HIGH;
    }
}
