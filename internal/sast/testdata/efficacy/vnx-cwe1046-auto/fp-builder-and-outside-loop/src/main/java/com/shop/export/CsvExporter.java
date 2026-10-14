package com.shop.export;

public class CsvExporter {

    public String header(List<Column> columns) {
        StringBuilder csv = new StringBuilder();
        for (Column column : columns) {
            csv.append(column.getName()).append(',');
        }
        return csv.toString();
    }

    public String title(List<Column> columns) {
        String title = "Export";
        for (Column column : columns) {
            validate(column);
        }
        title += " (" + columns.size() + " columns)";
        return title;
    }
}
