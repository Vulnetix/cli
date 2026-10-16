package app;
public class A {
    private int n;
    public void dec() {
~>        synchronized (new Object()) {
            n--;
        }
    }
}
