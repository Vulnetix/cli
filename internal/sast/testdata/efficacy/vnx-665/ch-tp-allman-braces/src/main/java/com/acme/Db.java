package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;

public class Db
{
    private static Connection conn;

    static
    {
        try
        {
            conn = DriverManager.getConnection(System.getenv("DB_URL"));
        }
~>        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
