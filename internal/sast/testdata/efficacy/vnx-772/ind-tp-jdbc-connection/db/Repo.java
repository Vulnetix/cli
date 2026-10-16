package db;

import java.sql.*;
import javax.sql.DataSource;

public class Repo {
    private DataSource ds;

    public int count() throws SQLException {
~>        Connection conn = ds.getConnection();
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("select count(*) from t");
        rs.next();
        return rs.getInt(1);
    }
}
