package app;

public class Config {
    // Integer.parseInt(request.getParameter("x")) would throw
    private static final int PORT = Integer.parseInt("8080");
    private final int threads = Integer.parseInt(System.getProperty("threads", "4"));
    private final String help = "Integer.parseInt(request.getParameter(\"page\"))";

    public int retries(Properties props) {
        return Integer.parseInt(props.getProperty("retries"));
    }
}
