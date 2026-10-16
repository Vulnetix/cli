package app;
import java.util.ArrayList;
import java.util.List;
public class F {
    private final Object lock = new Object();
    private final List<String> items = new ArrayList<>();
    private static int total;
    private int n;
    public void a() { synchronized (this) { n++; } }
    public void b() { synchronized (lock) { n++; } }
    public void c() { synchronized (items) { items.add("x"); } }
    public void d() { synchronized (F.class) { total++; } }
    public static synchronized void e() { total++; }
    public synchronized void f() { n++; }
}
