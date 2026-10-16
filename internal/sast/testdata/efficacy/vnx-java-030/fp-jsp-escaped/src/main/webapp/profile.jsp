<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<html>
<body>
<p>Name: <c:out value="${param.name}"/></p>
<p>Escaped: <%= org.owasp.encoder.Encode.forHtml(request.getParameter("name")) %></p>
<%
    String who = request.getHeader("X-User");
    int page = Integer.parseInt(request.getParameter("page"));
%>
<p>Page <%= page %></p>
<p>Header <%= org.springframework.web.util.HtmlUtils.htmlEscape(who) %></p>
<p>Static <%= "fixed" %> and <%= 1 + 2 %></p>
<%
    out.println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(who));
%>
</body>
</html>
