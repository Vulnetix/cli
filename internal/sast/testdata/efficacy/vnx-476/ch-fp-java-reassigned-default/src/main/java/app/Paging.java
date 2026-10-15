package app;

import javax.servlet.http.HttpServletRequest;

public class Paging {
    String sort(HttpServletRequest request) {
        String sort = request.getParameter("sort");
        sort = StringUtils.defaultString(sort, "name");
        return sort.toLowerCase();
    }
}
