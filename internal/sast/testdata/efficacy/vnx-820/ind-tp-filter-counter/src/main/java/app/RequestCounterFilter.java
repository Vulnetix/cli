package app;

import javax.servlet.*;
import java.io.IOException;

public class RequestCounterFilter implements Filter {
    private long served;

    public void doFilter(ServletRequest rq, ServletResponse rs, FilterChain c) throws IOException, ServletException {
~>        served++;
        c.doFilter(rq, rs);
    }
}
