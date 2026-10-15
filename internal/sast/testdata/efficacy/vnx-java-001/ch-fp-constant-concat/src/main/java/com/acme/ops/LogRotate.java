package com.acme.ops;

public class LogRotate {
    private static final String LOG_DIR = "/var/log/acme";
    private static final String ROTATE = "logrotate -f";

    public void rotate() throws Exception {
        Runtime.getRuntime().exec(ROTATE + " " + LOG_DIR + "/acme.conf");
        Runtime.getRuntime().exec("du -sh " + LOG_DIR);
        new ProcessBuilder("sh", "-c", "find " + LOG_DIR + " -mtime +7 -delete").start();
    }
}
