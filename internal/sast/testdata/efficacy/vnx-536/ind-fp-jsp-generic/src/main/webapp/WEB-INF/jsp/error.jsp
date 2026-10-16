<%@ page isErrorPage="true" contentType="text/html;charset=UTF-8" %>
<!doctype html>
<html>
<head><title>Something went wrong</title></head>
<body>
  <h1>Unexpected error</h1>
  <p>Reference: <%= request.getAttribute("jakarta.servlet.error.request_uri") %></p>
  <%-- do not print <%= exception.getMessage() %> here --%>
  <% application.log("error page shown", exception); %>
</body>
</html>
