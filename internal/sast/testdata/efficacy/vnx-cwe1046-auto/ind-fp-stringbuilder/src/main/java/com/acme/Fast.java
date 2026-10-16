package com.acme;

import java.util.List;
import java.util.stream.Collectors;

public class Fast {
    public String csv(List<Column> columns) {
        StringBuilder sb = new StringBuilder();
        for (Column c : columns) {
            sb.append(c.getName()).append(',');
        }
        String joined = columns.stream().map(Column::getName).collect(Collectors.joining(","));
        String s = "";
        s += joined;
        return sb.toString() + s;
    }
}
