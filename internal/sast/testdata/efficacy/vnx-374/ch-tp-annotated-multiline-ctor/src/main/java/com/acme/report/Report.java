package com.acme.report;

import java.util.List;
import java.util.Map;

public abstract class Report {
    private final String title;
    private final Map<String, List<Integer>> index;
    protected List<String> columns;

    protected Report(
            @NonNull String title,
            @NonNull Map<String, List<Integer>> index,
            List<String> columns) {
        this.title = title;
~>        this.index = index;
~>        this.columns = columns;
    }

    public String getTitle() {
        return title;
    }
}
