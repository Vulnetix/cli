package com.acme.db;

import java.util.Properties;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class DriverLoader {
    private static final String DRIVER = "org.postgresql.Driver";
    private static final Set<String> ALLOWED = Set.of("com.acme.jobs.Nightly", "com.acme.jobs.Hourly");

    public void load(Properties props) throws Exception {
        Class.forName("org.h2.Driver");
        Class.forName(DRIVER);
        Class.forName(props.getProperty("jdbc.driver"));
        Class<?> self = Class.forName(DriverLoader.class.getName());
    }

    public Object job(HttpServletRequest request) throws Exception {
        String job = request.getParameter("job");
        if (!ALLOWED.contains(job)) {
            throw new IllegalArgumentException("unknown job");
        }
        return Class.forName(job).getDeclaredConstructor().newInstance();
    }

    public void audit(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        System.out.println("Class.forName(request.getParameter(\"x\")) is unsafe for " + user);
        // Class.forName(request.getParameter("cls"));
        Class.forName(DRIVER);
    }
}
