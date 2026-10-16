package app;
import javax.servlet.http.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
public class Safe1 extends HttpServlet {
    private int hits;
    private final AtomicInteger atomic = new AtomicInteger();
    private final ConcurrentHashMap<String, String> m = new ConcurrentHashMap<>();
    private volatile boolean ready;
    protected synchronized void doGet(HttpServletRequest req, HttpServletResponse resp) {
        hits++;
        atomic.incrementAndGet();
        m.put("a", "b");
        ready = true;
    }
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        synchronized (this) {
            hits++;
        }
    }
}
