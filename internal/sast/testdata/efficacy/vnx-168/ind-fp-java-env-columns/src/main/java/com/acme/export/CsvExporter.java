package com.acme.export;

import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CsvExporter {

    private final String[] columns = System.getenv("EXPORT_COLUMNS").split(",");

    public void export(List<Row> rows, Path dir) throws IOException {
        try (Writer out = Files.newBufferedWriter(dir.resolve("export.csv"))) {
            out.write(String.join(",", columns));
            out.write("\n");
            for (Row r : rows) {
                out.write(r.toCsvLine(columns));
                out.write("\n");
            }
        }
    }
}
