package acme

import java.sql.DriverManager

fun open(url: String, user: String, pass: String) =
    DriverManager.getConnection(url, user, pass)
