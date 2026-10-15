<%@ page isErrorPage="true" %>
<html>
<body>
<h1>Something went wrong</h1>
<p>Please contact support with reference <%= request.getAttribute("requestId") %></p>
<% log("error page", exception); %>
</body>
</html>
