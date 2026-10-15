package com.shop.ops;

import java.io.IOException;

public class Backup {

    public void dump(String user, String password, String db) throws IOException {
~>        new ProcessBuilder("mysqldump", "-u", user, "--password=" + password, db).start();
    }

    public void restore(String dbPassword) throws IOException {
~>        String cmd = "mysql -u root -p" + dbPassword + " shop";
        Runtime.getRuntime().exec(cmd);
    }
}
