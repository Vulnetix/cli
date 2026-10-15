package com.acme.win;

import javax.servlet.http.HttpServletRequest;

public class ListingService {
    public void list(HttpServletRequest request) throws Exception {
        String folder = request.getParameter("folder");
~>        Process p = new ProcessBuilder("cmd.exe", "/c", "dir " + folder).start();
        p.waitFor();
    }
}
