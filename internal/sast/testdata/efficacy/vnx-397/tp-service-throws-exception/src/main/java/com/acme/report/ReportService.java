package com.acme.report;

import java.nio.file.Path;

public class ReportService {
~>    public Report build(long id) throws Exception {
        return assembler.assemble(repository.load(id));
    }

~>    private void export(Report r, Path out) throws Exception{
        writer.write(r, out);
    }

~>    static byte[] render(Report r) throws java.lang.Exception {
        return renderer.render(r);
    }
}
