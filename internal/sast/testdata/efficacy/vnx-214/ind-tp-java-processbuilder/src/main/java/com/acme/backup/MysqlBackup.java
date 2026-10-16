package com.acme.backup;

import java.io.File;
import java.io.IOException;

public class MysqlBackup {
    public int run(String user, String password, String database, File out)
            throws IOException, InterruptedException {
~>        ProcessBuilder pb = new ProcessBuilder("mysqldump", "-u", user, "-p" + password, database);
        pb.redirectOutput(out);
        return pb.start().waitFor();
    }
}
