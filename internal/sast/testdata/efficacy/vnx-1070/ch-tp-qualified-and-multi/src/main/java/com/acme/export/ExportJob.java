package com.acme.export;

import java.io.InputStream;

public class ExportJob extends AbstractJob
        implements Comparable<ExportJob>, java.io.Serializable {

    private final String name;
~>    protected InputStream source, overflow;
~>    private volatile java.util.concurrent.ExecutorService workers;

    public ExportJob(String name) {
        this.name = name;
    }

    public int compareTo(ExportJob other) {
        return name.compareTo(other.name);
    }
}
