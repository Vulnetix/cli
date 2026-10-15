package com.example.graph;

import java.util.ArrayList;
import java.util.List;

interface Copyable<T> {
    T clone();
}

public class Node implements Cloneable, Copyable<Node> {
    private List<Node> edges = new ArrayList<>();

    @Override
    public Node clone() {
        try {
            Node n =
                (Node) super
                    .clone();
            n.edges = new ArrayList<>(edges);
            return n;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
