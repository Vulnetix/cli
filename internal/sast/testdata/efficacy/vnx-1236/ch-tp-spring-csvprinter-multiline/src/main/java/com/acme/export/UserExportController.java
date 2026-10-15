package com.acme.export;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserExportController {

    private final UserRepository users;

    public UserExportController(UserRepository users) {
        this.users = users;
    }

    @GetMapping("/admin/users/export")
    public void export(HttpServletResponse response) throws IOException {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=users.csv");
        try (CSVPrinter printer = new CSVPrinter(response.getWriter(), CSVFormat.DEFAULT)) {
            for (User u : users.findAll()) {
~>                printer.printRecord(
                    u.getDisplayName(),
                    u.getEmail(),
                    u.getBio());
            }
        }
    }
}
