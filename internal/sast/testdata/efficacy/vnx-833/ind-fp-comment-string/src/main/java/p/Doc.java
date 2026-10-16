package p;

public class Doc {
    // synchronized (a) { synchronized (b) { ... } }
    // synchronized (b) { synchronized (a) { ... } }
    static final String HELP = "synchronized (x) { synchronized (y) { } } then synchronized (y) { synchronized (x) { } }";
}
