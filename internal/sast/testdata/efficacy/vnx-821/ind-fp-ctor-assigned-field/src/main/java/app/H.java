package app;
public class H {
    private Object mon;
    private int v;
    public H(Object m) { this.mon = m; }
    public void put(int x) {
        synchronized (mon) { v = x; }
    }
}
