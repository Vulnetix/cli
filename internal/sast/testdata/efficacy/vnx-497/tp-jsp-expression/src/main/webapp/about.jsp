<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<body>
<h1>About</h1>
~><p>Server JVM: <%= System.getProperty("java.version") %></p>
~><p>Path: <% out.println(System.getenv("PATH")); %></p>
</body>
</html>
