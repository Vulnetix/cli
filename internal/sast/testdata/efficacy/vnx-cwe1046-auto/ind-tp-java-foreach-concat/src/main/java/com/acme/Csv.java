package com.acme;

import java.util.List;

public class Csv {
    public String header(List<Column> columns) {
        String csv = "";
        for (Column column : columns) {
~>            csv += column.getName() + ",";
        }
        return csv;
    }
}
