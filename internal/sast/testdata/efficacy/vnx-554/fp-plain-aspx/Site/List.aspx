<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="List.aspx.cs" Inherits="Site.List" %>
<html>
<body>
  <% foreach (var item in Items) { %>
    <li><%: item.Name %></li>
  <% } %>
</body>
</html>
