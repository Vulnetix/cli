package com.acme.report;

import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;

public class ReportCursor implements Serializable {
~>    private Connection connection;
~>    private ResultSet rows;
    private int position;
}
