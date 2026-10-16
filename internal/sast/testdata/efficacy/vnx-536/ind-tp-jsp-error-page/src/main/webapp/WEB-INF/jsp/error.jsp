<%@ page isErrorPage="true" contentType="text/html;charset=UTF-8" %>
<!doctype html>
<html>
<head><title>Something went wrong</title></head>
<body>
  <h1>Unexpected error</h1>
~>  <p class="detail"><%= exception.getMessage() %></p>
  <p><a href="<%= request.getContextPath() %>/">Back to the home page</a></p>
</body>
</html>
