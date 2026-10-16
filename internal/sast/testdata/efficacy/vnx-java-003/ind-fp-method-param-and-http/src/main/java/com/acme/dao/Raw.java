package com.acme.dao;

import java.sql.*;
import java.util.concurrent.ExecutorService;

public class Raw {
    public boolean run(Statement st, String sql) throws SQLException {
        return st.execute(sql);
    }

    public void submit(ExecutorService executor, Runnable task) {
        executor.execute(task);
    }
}
