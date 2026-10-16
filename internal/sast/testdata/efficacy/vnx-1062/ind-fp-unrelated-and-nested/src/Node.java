package t;

public abstract class Node {
    static final class Leaf extends Node { }

    public static Node make() {
        return new Leaf();
    }

    public boolean isLeafLike(Object o) {
        return o instanceof Leaflet;
    }
}
