package web;

import java.io.IOException;
import java.util.UUID;
import jakarta.servlet.http.*;

public class OrderServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String ref = req.getHeader("X-Order-Ref");
~>        UUID orderId = UUID.fromString(ref);
        process(orderId);
    }
}
