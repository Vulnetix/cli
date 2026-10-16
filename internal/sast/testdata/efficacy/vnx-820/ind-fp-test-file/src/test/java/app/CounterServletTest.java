package app;
import javax.servlet.http.*;
public class CounterServletTest extends HttpServlet {
    private int hits;
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) { hits++; }
}
