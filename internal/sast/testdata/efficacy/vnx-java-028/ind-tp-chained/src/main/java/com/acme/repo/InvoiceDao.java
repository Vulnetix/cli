package com.acme.repo;

import java.sql.*;

public class InvoiceDao {
    void close(Statement stmt, String number) throws SQLException {
~>        stmt.executeUpdate(new StringBuilder("UPDATE invoices SET closed = 1 WHERE number = ").append(number).toString());
    }
}
