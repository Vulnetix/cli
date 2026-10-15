package com.acme.legacy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class ShopRepository {

    Connection open() throws SQLException {
~>        return @@sample:D[r]iv[e]rM[a]na[g]er[.]ge[t]Co[n]ne[c]ti[o]n@@(
                "jdbc:mysql://db.shop.internal:3306/shop",
                "shop",
                "Sh0pAdm1n#");
    }

    Connection openReadOnly(String url) throws SQLException {
~>        return @@sample:D[r]iv[e]rM[a]na[g]er[.]ge[t]Co[n]ne[c]ti[o]n@@(url, "reader", "r3ad0nly!");
    }
}
