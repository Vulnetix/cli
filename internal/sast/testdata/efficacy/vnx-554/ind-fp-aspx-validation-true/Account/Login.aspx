<%@ Page Title="Sign in" Language="C#" ValidateRequest="true" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="Site.Account.Login" %>
<%-- ValidateRequest="false" must never be set on this page --%>
<asp:Content ID="Body" ContentPlaceHolderID="MainContent" runat="server">
    <asp:Login ID="LoginForm" runat="server" />
</asp:Content>
