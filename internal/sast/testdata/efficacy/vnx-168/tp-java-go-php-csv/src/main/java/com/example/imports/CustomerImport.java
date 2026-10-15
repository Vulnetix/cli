package com.example.imports;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;

public class CustomerImport {
    public void run(Path dir) throws Exception {
        try (BufferedReader in = Files.newBufferedReader(dir.resolve("customers.csv"))) {
            String line;
            while ((line = in.readLine()) != null) {
~>                String[] cols = line.split(",");
                save(cols[0], cols[1], cols[2]);
            }
        }
    }
}
