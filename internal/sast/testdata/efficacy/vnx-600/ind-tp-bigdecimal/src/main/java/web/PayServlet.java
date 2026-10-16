package web;

import java.io.IOException;
import java.math.BigDecimal;
import javax.servlet.http.*;

public class PayServlet extends HttpServlet {
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String amt = req.getParameter("amount");
~>        BigDecimal amount = new BigDecimal(amt);
        charge(amount);
    }
}
