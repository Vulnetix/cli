package com.acme.report;

import java.io.BufferedReader;
import java.io.FileReader;
import javax.servlet.http.HttpServletRequest;

public class ReportController {
    private static final String ROOT = "/opt/reports";

    public String show(HttpServletRequest request) throws Exception {
        String fname = String.format("%s/%s.txt", ROOT, request.getParameter("doc"));
~>        try (BufferedReader r = new BufferedReader(new FileReader(fname))) {
            return r.readLine();
        }
    }
}
