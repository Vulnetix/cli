package app;

import java.net.URI;
import javax.servlet.*;
import javax.servlet.http.*;

public class AdminFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws java.io.IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        String path = URI.create(request.getRequestURI()).normalize().getPath().toLowerCase();
        if (path.startsWith("/admin") && request.getUserPrincipal() == null) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}
