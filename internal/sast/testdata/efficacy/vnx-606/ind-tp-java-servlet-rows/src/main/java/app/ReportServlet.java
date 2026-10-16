package app;

import javax.servlet.http.*;
import java.io.IOException;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int rows = Integer.parseInt(request.getParameter("rows"));
        StringBuilder out = new StringBuilder();
~>        for (int i = 0; i < rows; i++) {
            out.append(renderRow(i)).append('\n');
        }
        response.getWriter().write(out.toString());
    }

    private String renderRow(int i) { return "row " + i; }
}
