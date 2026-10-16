package com.acme;

import com.opencsv.CSVWriter;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;

public class ExportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/csv");
        resp.setHeader("Content-Disposition", "attachment; filename=\"members.csv\"");
        try (CSVWriter w = new CSVWriter(resp.getWriter())) {
            w.writeNext(new String[] {"name", "note"});
            for (Member m : repo.all()) {
~>                w.writeNext(new String[] {m.getName(), m.getNote()});
            }
        }
    }
}
