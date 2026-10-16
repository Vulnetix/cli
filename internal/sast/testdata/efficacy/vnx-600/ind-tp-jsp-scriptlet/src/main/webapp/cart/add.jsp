<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="com.acme.cart.Cart" %>
<%
    Cart cart = (Cart) session.getAttribute("cart");
~>    int qty = Integer.parseInt(request.getParameter("qty"));
    cart.add(request.getParameter("sku"), qty);
%>
<p>Added <%= qty %> item(s) to your cart.</p>
