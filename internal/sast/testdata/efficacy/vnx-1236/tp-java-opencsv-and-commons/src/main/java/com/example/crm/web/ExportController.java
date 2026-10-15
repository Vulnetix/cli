package com.example.crm.web;

import com.opencsv.CSVWriter;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {

    @GetMapping("/export/contacts")
    public void contacts(HttpServletResponse response) throws Exception {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=contacts.csv");
        CSVWriter writer = new CSVWriter(response.getWriter());
        writer.writeNext(new String[] {"Name", "Company"});
        for (Contact c : contacts.findAll()) {
~>            writer.writeNext(new String[] {c.getName(), c.getCompany()});
        }
        writer.close();
    }

    @GetMapping(value = "/export/notes", produces = "text/csv")
    public void notes(HttpServletResponse response) throws Exception {
        CSVPrinter printer = new CSVPrinter(response.getWriter(), CSVFormat.DEFAULT);
        for (Note n : notes.findAll()) {
~>            printer.printRecord(n.getId(), n.getAuthor(), n.getText());
        }
        printer.flush();
    }
}
