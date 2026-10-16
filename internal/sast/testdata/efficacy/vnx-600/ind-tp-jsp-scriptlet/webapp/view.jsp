<%@ page language="java" %>
<html>
<body>
<%
~>    long page = Long.parseLong(request.getParameter("page"));
    out.println(page);
%>
</body>
</html>
