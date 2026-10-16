package com.acme.reports;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class ReportDao {
    private Statement stmt;

    public ResultSet echoed(HttpServletRequest request) throws SQLException {
        Lookup lookup = new Lookup();
        String table = lookup.same(request.getParameter("table"));
~>        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet inline(HttpServletRequest request) throws SQLException {
        Lookup lookup = new Lookup();
~>        return stmt.executeQuery("SELECT * FROM " + lookup.same(request.getParameter("table")));
    }

    public ResultSet constructorStored(HttpServletRequest request) throws SQLException {
        Filter filter = new Filter(request.getParameter("filter"));
        String clause = filter.clause();
~>        return stmt.executeQuery("SELECT * FROM reports WHERE " + clause);
    }

    public ResultSet readsRequest(HttpServletRequest request) throws SQLException {
        RequestReader reader = new RequestReader(request);
        String table = reader.param("table");
~>        ResultSet a = stmt.executeQuery("SELECT * FROM " + table);
        String clause = reader.header();
~>        ResultSet b = stmt.executeQuery("SELECT * FROM reports WHERE " + clause);
        return b;
    }

    public ResultSet replaced(HttpServletRequest request) throws SQLException {
        SettableFilter filter = new SettableFilter("status = 'open'");
        filter.replace(request.getParameter("filter"));
        String clause = filter.clause();
~>        return stmt.executeQuery("SELECT * FROM reports WHERE " + clause);
    }

    public ResultSet override(HttpServletRequest request) throws SQLException {
        Ordering ordering = chooseOrdering();
        String column = ordering.column(request.getParameter("sort"));
~>        return stmt.executeQuery("SELECT * FROM reports ORDER BY " + column);
    }

    public ResultSet twoClassesOneName(HttpServletRequest request) throws SQLException {
        com.acme.reports.left.Names names = new com.acme.reports.left.Names();
        String table = names.table(request.getParameter("table"));
~>        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet unknownClass(HttpServletRequest request) throws SQLException {
        String table = Registry.resolve(request.getParameter("table"));
~>        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet chained(HttpServletRequest request) throws SQLException {
        Pager pager = new Pager();
        Lookup lookup = new Lookup();
        String table = pager.keep(lookup.same(request.getParameter("table")));
~>        return stmt.executeQuery("SELECT * FROM " + table);
    }

    public ResultSet overloaded(HttpServletRequest request) throws SQLException {
        Quoter quoter = new Quoter();
        String column = quoter.column("created_at", request.getParameter("sort"));
~>        return stmt.executeQuery("SELECT * FROM reports ORDER BY " + column);
    }

    private Ordering chooseOrdering() {
        return new ByRequest();
    }
}
