package app;

import javax.servlet.http.*;

public class AdminTest {
    void t(HttpServletRequest request) {
        if ("true".equals(request.getParameter("isAdmin"))) { }
    }
}
