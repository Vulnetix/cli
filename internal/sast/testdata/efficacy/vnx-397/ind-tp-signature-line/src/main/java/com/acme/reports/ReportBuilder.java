package com.acme.reports;

import java.util.List;

public class ReportBuilder {
    private final ReportRepository repo;

    public ReportBuilder(ReportRepository repo) {
        this.repo = repo;
    }

~>    public Report build(long id) throws Exception {
        List<Row> rows = repo.rows(id);
        return new Report(id, rows);
    }

~>    protected static byte[] render(Report r) throws java.lang.Throwable {
        return r.toPdf();
    }
}
