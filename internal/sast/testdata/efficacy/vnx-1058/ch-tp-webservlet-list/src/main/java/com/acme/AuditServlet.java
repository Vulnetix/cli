package com.acme;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/audit")
public class AuditServlet extends javax.servlet.http.HttpServlet {
~>    static List<String> seen = new ArrayList<>();

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        seen.add(req.getRemoteAddr());
    }
}
