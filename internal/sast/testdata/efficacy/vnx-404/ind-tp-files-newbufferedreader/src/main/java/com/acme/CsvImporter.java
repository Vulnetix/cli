package com.acme;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CsvImporter {

    public List<String[]> importRows(Path csv) throws IOException {
        List<String[]> rows = new ArrayList<>();
~>        BufferedReader reader = Files.newBufferedReader(csv, StandardCharsets.UTF_8);
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            rows.add(line.split(","));
        }
        return rows;
    }
}
