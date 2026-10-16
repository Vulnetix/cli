package com.acme.sync;

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;

public class ReplicaWorker implements Runnable {
    private final DataSource source;

    public ReplicaWorker(DataSource source) {
        this.source = source;
    }

    @Override
    public void run() {
        try {
            Connection c = source.getConnection();
            c.setAutoCommit(false);
            replicate(c);
            c.commit();
~>        } catch (SQLException e) {
            // TODO Auto-generated catch block
        }
    }

    private void replicate(Connection c) throws SQLException {
        c.createStatement().execute("CALL replicate_pending()");
    }
}
