package com.acme;
import java.io.Serializable;
import org.slf4j.Logger;
import com.acme.model.Process;
public class Bank implements Serializable {
    private Logger log;
    private Process process;
    private Statement statement;
    private Connection link;
    private DataSource source;
    private ResultSet rows;
    private String note = "private Socket socket;";
    // private Thread t;
}
