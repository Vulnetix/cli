<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<body>
<h2>Results</h2>
~><p>You searched for: <%= request.getParameter("q") %></p>
<%
    String sort = request.getParameter("sort");
    String who = request.getHeader("X-User");
%>
~><p>Sorted by <%= sort %></p>
<%
~>    out.println("<b>" + who + "</b>");
%>
<p>Safe constant: <%= "fixed" %></p>
</body>
</html>
