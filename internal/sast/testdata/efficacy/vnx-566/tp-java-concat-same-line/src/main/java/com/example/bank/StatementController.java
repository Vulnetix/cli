package com.example.bank;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class StatementController {
    private final Connection conn;

    public StatementController(Connection conn) {
        this.conn = conn;
    }

    public ResultSet statement(HttpServletRequest req) throws Exception {
        Statement st = conn.createStatement();
~>        return st.executeQuery("SELECT * FROM accounts WHERE account_id = " + req.getParameter("acct"));
    }

    public int close(HttpServletRequest req) throws Exception {
        String acct = req.getParameter("acct");
        Statement st = conn.createStatement();
~>        return st.executeUpdate("DELETE FROM accounts WHERE account_id = '" + acct + "'");
    }
}
