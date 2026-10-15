<%@ Page Language="C#" AutoEventWireup="true" ValidateRequest="true" CodeBehind="Default.aspx.cs" Inherits="Site._Default" %>
<html><body><%= Server.HtmlEncode(Request.QueryString["q"]) %></body></html>
