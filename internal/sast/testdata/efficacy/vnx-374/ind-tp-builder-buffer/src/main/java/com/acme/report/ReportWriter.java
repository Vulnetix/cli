package com.acme.report;

import java.util.Date;
import java.util.List;

public class ReportWriter {
    private StringBuilder buffer;
    private List<String> columns;
    private Date cutoff;

    public ReportWriter withBuffer(StringBuilder sb) {
~>        this.buffer = sb;
        return this;
    }

~>    public ReportWriter withColumns(final List<String> columns) { this.columns = columns; return this; }

    public void setCutoff(Date cutoff) {
~>        this.cutoff = cutoff;
    }
}
