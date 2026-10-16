package com.acme;

import java.sql.*;

public class ReportDao {
    private final Connection conn;
    public ReportDao(Connection conn) { this.conn = conn; }

    public ResultSet fleet(int owner) throws SQLException {
~>        String sql = "SELECT v.id, v.plate, d.name, m.last_service "
            + "FROM vehicles v "
            + "INNER JOIN drivers d ON d.vehicle_id = v.id "
            + "LEFT JOIN maintenance m ON m.vehicle_id = v.id "
            + "JOIN depots dp ON dp.id = v.depot_id "
            + "JOIN companies co ON co.id = dp.company_id "
            + "WHERE co.owner_id = ? AND v.id NOT IN (SELECT vehicle_id FROM recalls) ";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setInt(1, owner);
        return ps.executeQuery();
    }
}
