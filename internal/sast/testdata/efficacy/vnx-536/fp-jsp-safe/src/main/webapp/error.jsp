<%@ page isErrorPage="true" %>
<html>
<body>
<h1>Something went wrong</h1>
<p>Reference: <%= request.getAttribute("errorId") %></p>
<% application.log("error page", exception); %>
</body>
</html>
