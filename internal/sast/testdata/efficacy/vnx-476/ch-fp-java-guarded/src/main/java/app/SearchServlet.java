package app;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

public class SearchServlet {
    String query(HttpServletRequest request) {
        String q = request.getParameter("q");
        if (q != null && q.trim().length() > 0) {
            return q.trim();
        }
        String region = Optional.ofNullable(System.getenv("REGION")).orElse("eu");
        String agent = request.getHeader("User-Agent");
        if (agent == null) {
            return region;
        }
        return agent.toLowerCase();
    }
}
