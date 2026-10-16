package com.acme.web;

import java.io.IOException;
import javax.servlet.http.*;
import org.springframework.web.servlet.view.RedirectView;

public class Fixed {
    void a(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        resp.sendRedirect("/account?id=" + id);
    }

    RedirectView b() {
        return new RedirectView("https://www.example.com/home");
    }
}
