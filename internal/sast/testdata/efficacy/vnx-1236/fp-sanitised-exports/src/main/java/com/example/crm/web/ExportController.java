package com.example.crm.web;

import com.opencsv.CSVWriter;
import jakarta.servlet.http.HttpServletResponse;

public class ExportController {

    static String sanitizeCell(String v) {
        if (v != null && !v.isEmpty() && "=+-@".indexOf(v.charAt(0)) >= 0) {
            return "'" + v;
        }
        return v;
    }

    public void contacts(HttpServletResponse response, Iterable<Contact> all) throws Exception {
        response.setContentType("text/csv");
        CSVWriter writer = new CSVWriter(response.getWriter());
        for (Contact c : all) {
            writer.writeNext(new String[] {sanitizeCell(c.getName()), sanitizeCell(c.getCompany())});
        }
    }
}
