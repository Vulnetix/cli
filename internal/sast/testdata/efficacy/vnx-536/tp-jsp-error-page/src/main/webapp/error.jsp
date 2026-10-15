<%@ page isErrorPage="true" %>
<html>
<body>
<h1>Something went wrong</h1>
~><p><%= exception.getMessage() %></p>
~><% exception.printStackTrace(new java.io.PrintWriter(out)); %>
</body>
</html>
