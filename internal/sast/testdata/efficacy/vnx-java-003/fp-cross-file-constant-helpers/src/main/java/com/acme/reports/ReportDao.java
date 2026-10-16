package com.acme.reports;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class ReportDao {
    private Statement stmt;

    public ResultSet byTable() throws SQLException {
        TableNames tables = new TableNames();
        String table = tables.reports();
        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet viaStatic() throws SQLException {
        String table = TableNames.audit();
        return stmt.executeQuery("SELECT * FROM " + table + " WHERE level = 1");
    }

    public ResultSet inline() throws SQLException {
        TableNames tables = new TableNames();
        return stmt.executeQuery("SELECT * FROM " + tables.archive());
    }

    public ResultSet sanitized(HttpServletRequest request) throws SQLException {
        Quoter quoter = new Quoter();
        String name = quoter.quote(request.getParameter("name"));
        return stmt.executeQuery("SELECT * FROM reports WHERE owner = " + name);
    }

    public ResultSet chained() throws SQLException {
        TableNames tables = new TableNames();
        Pager pager = new Pager();
        String table = pager.keep(pager.keep(tables.reports()));
        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet storedLiteral() throws SQLException {
        Filter filter = new Filter("status = 'open'");
        String clause = filter.clause();
        return stmt.executeQuery("SELECT * FROM reports WHERE " + clause);
    }

    public ResultSet ordered(HttpServletRequest request) throws SQLException {
        Ordering ordering = new ByName();
        String column = ordering.column(request.getParameter("sort"));
        return stmt.executeQuery("SELECT * FROM reports ORDER BY " + column);
    }

    public ResultSet fallbackOnly(HttpServletRequest request) throws SQLException {
        Quoter quoter = new Quoter();
        String column = quoter.column(request.getParameter("sort"), "created_at");
        return stmt.executeQuery("SELECT * FROM reports ORDER BY " + column);
    }
}
