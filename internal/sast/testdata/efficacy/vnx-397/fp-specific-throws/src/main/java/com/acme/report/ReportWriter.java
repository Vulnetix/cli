package com.acme.report;

import java.io.IOException;
import java.sql.SQLException;

public class ReportWriter {
    public void write(Report r) throws IOException {
        out.write(r.bytes());
    }

    public Report load(long id) throws SQLException, ReportNotFoundException {
        return dao.load(id);
    }

    public void validate(Report r) throws ValidationException, ExceptionInInitializerError {
        rules.check(r);
    }

    public void fail() {
        throw new IllegalStateException("throws Exception is not allowed here");
    }
}
