package com.acme;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.concurrent.ExecutorService;
import java.io.InputStream;
public class Job implements Serializable, Runnable {
    private final long id;
~>    private Connection conn;
~>    private final ExecutorService pool;
~>    private InputStream payload, extra;
~>    private ResultSet cursor;
    public Job(long id, ExecutorService pool) { this.id = id; this.pool = pool; }
    public void run() {}
}
