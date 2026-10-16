package web;

import javax.servlet.http.HttpServlet;

public class AdminServletTest extends HttpServlet {
    void concurrent() throws Exception {
        Thread t = new Thread(() -> {});
        t.start();
        t.join();
    }
}
