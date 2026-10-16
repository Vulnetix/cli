package com.acme.graph;

import java.util.Objects;

public class Graph {
    private final String name;

    public Graph(String name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Graph && Objects.equals(name, ((Graph) o).name);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(name);
    }

    public static final class Edge {
        final int from;
        final int to;

        Edge(int from, int to) {
            this.from = from;
            this.to = to;
        }

        @Override
~>        public int hashCode() {
            return 31 * from + to;
        }
    }
}
