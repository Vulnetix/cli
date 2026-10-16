package app;
public class E {
    int a;
    void one() {
~>        synchronized (getClass()) { a++; }
    }
    void two() {
~>        synchronized (Boolean.TRUE) { a++; }
    }
}
