package com.acme.etl;

import com.opencsv.CSVWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/** Writes the nightly warehouse dump; never served over HTTP (see text/csv export elsewhere). */
public class NightlyDump {

    public void write(List<String[]> rows, String path) throws IOException {
        try (CSVWriter writer = new CSVWriter(new FileWriter(path))) {
            writer.writeAll(rows);
        }
    }
}
