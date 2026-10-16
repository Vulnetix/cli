package com.acme.auth;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;

public class Reader {
    Connection go(HttpServletRequest req, java.util.Properties props) throws Exception {
        String password = req.getParameter("password");
        String user = props.getProperty("db.user");
        return DriverManager.getConnection(props.getProperty("db.url"), user, password);
    }
}
