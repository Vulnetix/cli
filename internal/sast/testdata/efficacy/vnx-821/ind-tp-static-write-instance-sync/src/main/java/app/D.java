package app;
public class D {
    private static int total;
    public synchronized void add(int n) {
~>        total += n;
    }
}
