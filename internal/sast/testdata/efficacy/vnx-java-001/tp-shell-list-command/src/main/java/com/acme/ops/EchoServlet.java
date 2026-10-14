package com.acme.ops;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

public class EchoServlet {
    public void handle(HttpServletRequest request) throws IOException {
        String param = request.getHeader("X-Echo");
        List<String> argList = new ArrayList<>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);
        ProcessBuilder pb = new ProcessBuilder();
~>        pb.command(argList);
        pb.start();
    }
}
