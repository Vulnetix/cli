package com.shop.export;

import java.util.List;

public class CsvExporter {

    public String header(List<Column> columns) {
        String csv = "";
        for (Column column : columns) {
~>            csv += column.getName() + ",";
        }
        return csv;
    }
}
