package com.acme.onboarding;

import java.io.IOException;
import javax.servlet.http.*;

public class IdentityServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String ssn = req.getParameter("ssn");
~>        Cookie cookie = new Cookie("applicant_ssn", ssn);
        cookie.setMaxAge(3600);
        resp.addCookie(cookie);
        resp.sendRedirect("/onboarding/step-2");
    }
}
