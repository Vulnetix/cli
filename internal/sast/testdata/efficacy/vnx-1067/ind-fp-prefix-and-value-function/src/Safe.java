package repo;

import java.sql.*;
import java.util.List;

public class Safe {
    String a = "SELECT * FROM users WHERE name LIKE 'adm%'";
    String b = "SELECT * FROM users WHERE email = LOWER(:email)";
    String c = "SELECT DATE(created_at), COUNT(*) FROM users GROUP BY DATE(created_at) ORDER BY DATE(created_at)";
    String d = "SELECT UPPER(name) FROM users WHERE id = 5";

    void prefix(PreparedStatement ps, String q) throws SQLException {
        ps.setString(1, q + "%");
    }

    void log(String q) {
        System.out.println(String.format("progress 50%% for %s", q));
        // LIKE '%foo%' is slow
    }
}
