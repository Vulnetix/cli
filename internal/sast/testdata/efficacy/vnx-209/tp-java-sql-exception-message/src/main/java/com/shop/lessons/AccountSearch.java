package com.shop.lessons;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class AccountSearch {

    public Result search(String name) {
        try (Connection connection = dataSource.getConnection()) {
            Statement statement = connection.createStatement();
            return Result.ok(statement.executeQuery("SELECT * FROM accounts WHERE name = '" + name + "'"));
        } catch (SQLException sqle) {
~>            return Result.failed().output(sqle.getMessage() + "<br> query: " + name).build();
        }
    }

    public void lookup(HttpServletResponse response, String id) throws IOException {
        try {
            dao.find(id);
        } catch (SQLException e) {
~>            response.getWriter().println("Database error: " + e.getMessage());
        }
    }
}
