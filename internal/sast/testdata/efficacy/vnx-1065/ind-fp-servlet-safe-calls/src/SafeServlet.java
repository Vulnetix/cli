package web;

import javax.servlet.http.HttpServlet;
import javax.annotation.Resource;
import javax.enterprise.concurrent.ManagedExecutorService;

public class SafeServlet extends HttpServlet {
    @Resource
    ManagedExecutorService mes;
    private static final ThreadLocal<String> TL = new ThreadLocal<>();

    protected void doGet() {
        Thread t = Thread.currentThread();
        mes.submit(() -> t.getName());
        // System.exit(0) would be wrong here
        String doc = "new Thread(r).start() and System.exit(1)";
        Thread.sleep(10);
        Thread[] arr = new Thread[4];
        int myThreadCount = 0;
    }
}
