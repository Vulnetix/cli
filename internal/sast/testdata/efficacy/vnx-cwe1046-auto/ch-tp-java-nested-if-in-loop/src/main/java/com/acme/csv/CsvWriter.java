package com.acme.csv;

import java.util.List;

public class CsvWriter {
    public String write(List<List<String>> table) {
        String out = "";
        for (List<String> row : table) {
            for (String cell : row) {
                if (cell.contains(",")) {
~>                    out += "\"" + cell + "\",";
                } else {
~>                    out = out + cell + ",";
                }
            }
        }
        return out;
    }
}
