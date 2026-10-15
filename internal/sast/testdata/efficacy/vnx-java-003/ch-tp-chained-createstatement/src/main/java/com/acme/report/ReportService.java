package com.acme.report;

import java.sql.Connection;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class ReportService {
    private Connection connection;

    public ResultSet run(HttpServletRequest req) throws Exception {
        String sort = req.getParameter("sort");
        ResultSet rs = connection.createStatement()
~>                .executeQuery("SELECT id, total FROM invoices ORDER BY " + sort);
        return rs;
    }

    public void purge(HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        java.sql.Statement st = connection.createStatement();
~>        st.addBatch("DELETE FROM invoices WHERE id = " + id);
        st.executeBatch();
    }
}
