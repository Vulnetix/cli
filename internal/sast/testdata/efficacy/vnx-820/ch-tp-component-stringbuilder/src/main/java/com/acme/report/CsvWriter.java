package com.acme.report;

import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class CsvWriter {

    private final StringBuilder out = new StringBuilder();

    public String write(List<String[]> rows) {
~>        out.setLength(0);
        for (String[] row : rows) {
~>            out.append(String.join(",", row)).append('\n');
        }
        return out.toString();
    }
}
