package com.shop.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][m]at[h][.]N[u]mb[e]rU[t]il[s]@@;

public class PageServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        if (!NumberUtils.isDigits(request.getParameter("page"))) {
            response.setStatus(400);
            return;
        }
        int page = Integer.parseInt(request.getParameter("page"));
        render(response, page);
    }
}
