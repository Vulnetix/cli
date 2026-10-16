package app;
import javax.servlet.http.*;
import java.util.HashMap;
import java.util.Map;
public class Safe4 extends HttpServlet {
    private int count;
    private Map<String, String> cfg = new HashMap<>();
    public Safe4() { count = 0; }
    public void init() { cfg.put("a", "b"); count = 5; }
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        int count = 0;
        count++;
        Map<String, String> cfg = new HashMap<>();
        cfg.put("x", "y");
        // hits++;
    }
}
