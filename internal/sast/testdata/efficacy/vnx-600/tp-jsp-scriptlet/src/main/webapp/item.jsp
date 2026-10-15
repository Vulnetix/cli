<%@ page contentType="text/html" %>
<html>
<body>
<%
~>    int qty = Integer.parseInt(request.getParameter("qty"));
%>
<p>Quantity: <%= qty %></p>
</body>
</html>
