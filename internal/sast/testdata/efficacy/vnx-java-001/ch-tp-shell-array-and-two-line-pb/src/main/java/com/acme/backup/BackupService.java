package com.acme.backup;

import javax.servlet.http.HttpServletRequest;

public class BackupService {
    public void backup(HttpServletRequest request) throws Exception {
        String dir = request.getParameter("dir");
        String[] cmd = {"/bin/bash", "-c", "tar czf /backups/out.tgz " + dir};
~>        Runtime.getRuntime().exec(cmd);
    }

    public void extract(HttpServletRequest request) throws Exception {
        String archive = request.getParameter("archive");
        String script = "tar -xf " + archive + " -C /srv/import";
~>        ProcessBuilder pb = new ProcessBuilder("bash", "-c", script);
        pb.start();
    }
}
