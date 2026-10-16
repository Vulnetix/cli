package com.acme.ops;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class HealthProbe {
    // The request value is kept only on a branch 8 + 4 * 3 < 10 never takes.
    public Process ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        int attempts = 4;
        String target;
        if (8 + attempts * 3 < 10) target = host;
        else target = "127.0.0.1";
        return Runtime.getRuntime().exec("ping -c 1 " + target);
    }

    public Process disk(HttpServletRequest request) throws IOException {
        String mount = request.getParameter("mount");
        int level = 1;
        String path = level == 1 ? "/var" : mount;
        Runtime rt = Runtime.getRuntime();
        return rt.exec("df -h " + path);
    }

    public Process service(HttpServletRequest request) throws IOException {
        String unit = request.getParameter("unit");
        int profile = 2;
        String name;
        switch (profile) {
            case 1:
                name = unit;
                break;
            case 2:
                name = "nginx";
                break;
            default:
                name = unit;
                break;
        }
        return Runtime.getRuntime().exec("systemctl status " + name);
    }

    public Process echo(HttpServletRequest request) throws IOException {
        List<String> words = new ArrayList<String>();
        words.add(request.getParameter("word"));
        words.add("ready");
        words.set(0, "probe");
        String word = words.get(0);
        List<String> argv = new ArrayList<String>();
        argv.add("sh");
        argv.add("-c");
        argv.add("echo " + word);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argv);
        return pb.start();
    }

    public Process tail(HttpServletRequest request) throws IOException {
        Map<String, String> logs = new HashMap<String, String>();
        logs.put("app", "/var/log/app.log");
        logs.put("custom", request.getParameter("log"));
        String file = logs.get("app");
        return new ProcessBuilder("sh", "-c", "tail -n 50 " + file).start();
    }

    public Process uptime(HttpServletRequest request) throws IOException {
        String format = request.getParameter("format");
        String flag = uptimeFlag(format);
        return Runtime.getRuntime().exec("uptime " + flag);
    }

    private static String uptimeFlag(String format) {
        if ("pretty".equals(format)) {
            return "-p";
        }
        return "-s";
    }
}
