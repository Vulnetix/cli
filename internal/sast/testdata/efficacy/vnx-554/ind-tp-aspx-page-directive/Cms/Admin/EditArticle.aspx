~><%@ Page Title="Edit article" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" ValidateRequest="false" CodeBehind="EditArticle.aspx.cs" Inherits="Cms.Admin.EditArticle" %>

<asp:Content ID="Body" ContentPlaceHolderID="MainContent" runat="server">
    <h2>Edit article</h2>
    <asp:TextBox ID="ArticleBody" runat="server" TextMode="MultiLine" Rows="20" />
    <asp:Button ID="Save" runat="server" Text="Save" OnClick="Save_Click" />
</asp:Content>
