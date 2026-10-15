package com.acme.users;

import java.sql.Connection;
import java.sql.ResultSet;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class ProfileDao {
    private Connection conn;
    private JdbcTemplate jdbc;

    public ResultSet byName(javax.servlet.http.HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String sql = """
                SELECT id, email FROM profiles
                WHERE display_name = '%s'
                """.formatted(name);
~>        return conn.createStatement().executeQuery(sql);
    }

    @PostMapping("/email")
    public void email(@RequestParam String email, @RequestParam long id) {
~>        jdbc.update("UPDATE users SET email = '" + email + "' WHERE id = " + id);
    }
}
