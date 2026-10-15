package com.acme.repo;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class UserRepository {
    private static final Logger log = LoggerFactory.getLogger(UserRepository.class);
    private final Connection conn;

    public UserRepository(Connection conn) {
        this.conn = conn;
    }

    public Optional<String> name(long id) {
        try {
            return Optional.of(query(id));
        } catch (SQLException e) {
            log.error("lookup failed: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    public void delete(long id) {
        try {
            conn.createStatement().execute("DELETE FROM users WHERE id = " + id);
        } catch (SQLException e) {
            throw new IllegalStateException("delete failed: " + e.getMessage(), e);
        }
    }

    private String query(long id) throws SQLException {
        return "";
    }
}
