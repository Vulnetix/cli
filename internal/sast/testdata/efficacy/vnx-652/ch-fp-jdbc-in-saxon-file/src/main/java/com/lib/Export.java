package com.lib;

import @@sample:n[e]t[.][s]f[.][s]ax[o]n[.][s]9a[p]i[.][P]ro[c]es[s]or@@;
import java.sql.ResultSet;
import java.sql.Statement;

public class Export {
    ResultSet rows(Statement stmt, String table) throws Exception {
        String sql = "SELECT id, xml FROM exports WHERE tbl = '" + table + "'";
        return stmt.executeQuery(sql);
    }
}
